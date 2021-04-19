-module(hbbft_cc).

-export([init/4, get_coin/1, handle_msg/3, serialize/1, deserialize/2, status/1]).

-record(cc_data, {
          state = waiting :: waiting | done,
          sk :: tc_key_share:tc_key_share() | tpke_privkey:privkey(),
          %% Note: sid is assumed to be a unique nonce that serves as name of this common coin
          sid :: binary() | erlang_pbc:element(),
          n :: pos_integer(),
          f :: non_neg_integer(),
          shares = maps:new() :: #{non_neg_integer() => {non_neg_integer(), signature_share:sig_share()}}
         }).

-record(cc_serialized_data, {
          state = waiting :: waiting | done,
          sid :: binary(),
          n :: pos_integer(),
          f :: non_neg_integer(),
          shares :: #{non_neg_integer() => binary()}
         }).

-type cc_data() :: #cc_data{}.
-type cc_serialized_data() :: #cc_serialized_data{}.
-type serialized_share() :: binary().
-type share_msg() :: {share, serialized_share()}.

-export_type([cc_data/0, cc_serialized_data/0, share_msg/0]).

-spec status(undefined | cc_data()) -> undefined | map().
status(undefined) ->
    undefined;
status(CCData) ->
    #{state => CCData#cc_data.state,
      shares => serialize_shares(hbbft_utils:curve(CCData#cc_data.sk), CCData#cc_data.shares)
     }.

%% Figure12. Bullet1
%% Trusted Setup Phase: A trusted dealer runs pk, {ski } ←
%% ThresholdSetup to generate a common public key, as well as
%% secret key shares {ski }, one for each party (secret key ski is
%% distributed to party Pi). Note that a single setup can be used to
%% support a family of Coins indexed by arbitrary sid strings.
-spec init(tc_key_share:tc_key_share(),
           binary(),
           pos_integer(),
           non_neg_integer()) -> cc_data().
init(KeyShare, Sid0, N, F) ->
    Sid = case tc_key_share:is_key_share(KeyShare) of
              true ->
                  Sid0;
              false ->
                  tpke_pubkey:hash_message(tpke_privkey:public_key(KeyShare), Sid0)
          end,
    #cc_data{sk=KeyShare, n=N, f=F, sid=Sid}.

%% Figure12. Bullet2
%% on input GetCoin, multicast ThresholdSignpk (ski, sid)
-spec get_coin(cc_data()) -> {cc_data(), ok | {send, [hbbft_utils:multicast(share_msg())]}}.
get_coin(Data = #cc_data{state=done}) ->
    {Data, ok};
get_coin(Data = #cc_data{sk=SK}) ->
    case hbbft_utils:curve(SK) of
        'BLS12-381' ->
            Share = tc_key_share:sign_share(Data#cc_data.sk, Data#cc_data.sid),
            {Data, {send, [{multicast, {share, hbbft_utils:sig_share_to_binary('BLS12-381', Share)}}]}};
        'SS512' ->
            Share = tpke_privkey:sign(Data#cc_data.sk, Data#cc_data.sid),
            SerializedShare = hbbft_utils:sig_share_to_binary('SS512', Share),
            {Data, {send, [{multicast, {share, SerializedShare}}]}}
    end.


%% upon receiving at least f + 1 shares, attempt to combine them
%% into a signature:
%% sig ← ThresholdCombinepk ({ j, s j })
%% if ThresholdVerifypk(sid) then deliver sig
%% TODO: more specific return type than an integer?
-spec handle_msg(cc_data(), non_neg_integer(), share_msg()) -> {cc_data(), ok | {result, integer()}} | ignore.
handle_msg(Data, J, {share, Share}) ->
    share(Data, J, Share).

%% TODO: more specific return type than an integer?
-spec share(cc_data(), non_neg_integer(), binary()) -> {cc_data(), ok | {result, integer()}} | ignore.
share(#cc_data{state=done}, _J, _Share) ->
    ignore;
share(Data=#cc_data{sk=SK}, J, Share) ->
    case maps:is_key(J, Data#cc_data.shares) of
        false ->
            Curve = hbbft_utils:curve(SK),
            DeserializedShare = hbbft_utils:binary_to_sig_share(Curve, SK, Share),
            ValidShare = case Curve of
                             'BLS12-381' ->
                                 tc_key_share:verify_signature_share(Data#cc_data.sk,
                                                                          DeserializedShare,
                                                                          Data#cc_data.sid);
                             'SS512' ->
                                 tpke_pubkey:verify_signature_share(tpke_privkey:public_key(Data#cc_data.sk), DeserializedShare, Data#cc_data.sid)
                         end,
            case ValidShare of
                true ->
                    %% store the deserialized share in the shares map, convenient to use later to verify signature
                    NewData = Data#cc_data{shares=maps:put(J, DeserializedShare, Data#cc_data.shares)},
                    %% check if we have at least f+1 shares
                    case maps:size(NewData#cc_data.shares) > Data#cc_data.f of
                        true ->
                            %% combine shares
                            {ok, Sig} = case Curve of
                                            'BLS12-381' ->
                                                tc_key_share:combine_signature_shares(SK, maps:values(NewData#cc_data.shares));
                                            'SS512' ->
                                                tpke_pubkey:combine_verified_signature_shares(tpke_privkey:public_key(NewData#cc_data.sk), maps:values(NewData#cc_data.shares))
                                        end,
                            %% check if the signature is valid
                            ValidSignature = case Curve of
                                                 'BLS12-381' ->
                                                     tc_key_share:verify(NewData#cc_data.sk, Sig, NewData#cc_data.sid);
                                                 'SS512' ->
                                                     tpke_pubkey:verify_signature(tpke_privkey:public_key(NewData#cc_data.sk), Sig, NewData#cc_data.sid)
                                             end,
                            case ValidSignature of
                                true ->
                                    %% TODO do something better here!
                                    <<Val:32/integer, _/binary>> = case Curve of
                                                                       'BLS12-381' -> signature:serialize(Sig);
                                                                       'SS512' -> erlang_pbc:element_to_binary(Sig)
                                                                   end,
                                    {NewData#cc_data{state=done}, {result, Val}};
                                false ->
                                    {NewData, ok}
                            end;
                        false ->
                            {NewData, ok}
                    end;
                false ->
                    %% XXX bad share can be proof of malfeasance
                    {Data, ok}
            end;
        true ->
            ignore
    end.

-spec serialize(cc_data()) -> cc_serialized_data().
serialize(#cc_data{state = State, sid = SID, n = N, sk = SK, f = F, shares = Shares}) ->
    #cc_serialized_data{
        state = State,
        sid = serialize_sid(SID),
        n = N,
        f = F,
        shares = serialize_shares(hbbft_utils:curve(SK), Shares)
    }.

-spec deserialize(cc_serialized_data(), tc_key_share:tc_key_share() | tpke_privkey:privkey()) ->
    cc_data().
deserialize(#cc_serialized_data{state = State, sid = SID, n = N, f = F, shares = Shares}, SK) ->
    #cc_data{
        state = State,
        sk = SK,
        sid = deserialize_sid(SK, SID),
        n = N,
        f = F,
        shares = deserialize_shares(hbbft_utils:curve(SK), SK, Shares)
    }.

-spec serialize_shares('BLS12-381' | 'SS512', #{non_neg_integer() => signature_share:sig_share()}) -> #{non_neg_integer() => binary()}.
serialize_shares(Curve, Shares) ->
    maps:map(fun(_K, V) -> hbbft_utils:sig_share_to_binary(Curve, V) end, Shares).

-spec deserialize_shares('BLS12-381' | 'SS512', tc_key_share:tc_key_share() | tpke_privkey:privkey(), #{non_neg_integer() => binary()}) -> #{non_neg_integer() => signature_share:sig_share()}.
deserialize_shares(Curve, SK, Shares) ->
    maps:map(fun(_K, V) -> hbbft_utils:binary_to_sig_share(Curve, SK, V) end, Shares).

serialize_sid(SID) when is_binary(SID) ->
    SID;
serialize_sid(SID) ->
    erlang_pbc:element_to_binary(SID).

deserialize_sid(SK, SID) ->
    case hbbft_utils:curve(SK) of
        'BLS12-381' -> SID;
        'SS512' -> tpke_pubkey:deserialize_element(tpke_privkey:public_key(SK), SID)
    end.

