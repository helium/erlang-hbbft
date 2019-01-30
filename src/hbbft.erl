-module(hbbft).

-export([init/6, init/7, init/9,
         get_stamp_fun/1,
         set_stamp_fun/4,
         start_on_demand/1,
         input/2,
         finalize_round/3,
         finalize_round/2,
         next_round/1,
         next_round/3,
         round/1,
         buf/1, buf/2,
         get_encrypted_key/2,
         encrypt/2,
         decrypt/2,
         handle_msg/3,
         serialize/1,
         serialize/2,
         deserialize/2,
         status/1,
         is_serialized/1]).

-record(hbbft_data, {
          batch_size :: pos_integer(),
          secret_key :: tpke_privkey:privkey(),
          n :: pos_integer(),
          f :: pos_integer(),
          j :: non_neg_integer(),
          round = 0 :: non_neg_integer(),
          buf = [] :: [binary()],
          max_buf = infinity :: infinity | pos_integer(),
          acs :: hbbft_acs:acs_data(),
          acs_init = false :: boolean(),
          sent_txns = false :: boolean(),
          sent_sig = false :: boolean(),
          acs_results = [] :: [{non_neg_integer(), binary()}],
          dec_shares = #{} :: #{{non_neg_integer(), non_neg_integer()} => {boolean() | undefined, {non_neg_integer(), erlang_pbc:element()}}},
          decrypted = #{} :: #{non_neg_integer() => [binary()]},
          sig_shares = #{} :: #{non_neg_integer() => {non_neg_integer(), erlang_pbc:element()}},
          thingtosign :: undefined | erlang_pbc:element(),
          stampfun :: undefined | {atom(), atom(), list()},
          stamps = [] :: [{non_neg_integer(), any()}]
         }).

-record(hbbft_serialized_data, {
          batch_size :: pos_integer(),
          n :: pos_integer(),
          f :: pos_integer(),
          j :: non_neg_integer(),
          round = 0 :: non_neg_integer(),
          buf = [] :: [binary()],
          max_buf = infinity :: infinity | pos_integer(),
          acs :: hbbft_acs:acs_serialized_data(),
          acs_init = false :: boolean(),
          sent_txns = false :: boolean(),
          sent_sig = false :: boolean(),
          acs_results = [] :: [{non_neg_integer(), binary()}],
          decrypted = #{} :: #{non_neg_integer() => [binary()]},
          sig_shares = #{} :: #{{non_neg_integer(), non_neg_integer()} => {boolean() | undefined, {non_neg_integer(), binary()}}},
          dec_shares = #{} :: #{non_neg_integer() => {non_neg_integer(), binary()}},
          thingtosign :: undefined | binary(),
          stampfun :: undefined | {atom(), atom(), list()},
          stamps = [] :: [{non_neg_integer(), any()}]
         }).

-type hbbft_data() :: #hbbft_data{}.
-type hbbft_serialized_data() :: #hbbft_serialized_data{}.
-type acs_msg() :: {{acs, non_neg_integer()}, hbbft_acs:msgs()}.
-type dec_msg() :: {dec, non_neg_integer(), non_neg_integer(), {non_neg_integer(), binary()}}.
-type sign_msg() :: {sign, non_neg_integer(), binary()}.
-type rbc_wrapped_output() :: hbbft_utils:unicast({{acs, non_neg_integer()}, {{rbc, non_neg_integer()}, hbbft_rbc:val_msg()}}) | hbbft_utils:multicast({{acs, non_neg_integer()}, {{rbc, non_neg_integer()}, hbbft_rbc:echo_msg() | hbbft_rbc:ready_msg()}}).
-type bba_wrapped_output() :: hbbft_utils:multicast({{acs, non_neg_integer()}, hbbft_acs:bba_msg()}).

-spec status(hbbft_data()) -> map().
status(HBBFTData) ->
    #{batch_size => HBBFTData#hbbft_data.batch_size,
      buf => length(HBBFTData#hbbft_data.buf),
      max_buf => HBBFTData#hbbft_data.max_buf,
      round => HBBFTData#hbbft_data.round,
      acs_init => HBBFTData#hbbft_data.acs_init,
      acs => hbbft_acs:status(HBBFTData#hbbft_data.acs),
      sent_txns => HBBFTData#hbbft_data.sent_txns,
      sent_sig => HBBFTData#hbbft_data.sent_sig,
      acs_results => length(HBBFTData#hbbft_data.acs_results),
      decryption_shares => group_by(maps:keys(HBBFTData#hbbft_data.dec_shares)),
      decrypted => maps:size(HBBFTData#hbbft_data.decrypted),
      j => HBBFTData#hbbft_data.j
     }.

-spec init(tpke_privkey:privkey(), pos_integer(), non_neg_integer(), non_neg_integer(), pos_integer(), infinity | pos_integer()) -> hbbft_data().
init(SK, N, F, J, BatchSize, MaxBuf) ->
    init(SK, N, F, J, BatchSize, MaxBuf, undefined, 0, []).
    #hbbft_data{secret_key=SK, n=N, f=F, j=J, batch_size=BatchSize, acs=hbbft_acs:init(SK, N, F, J), max_buf=MaxBuf}.

-spec init(tpke_privkey:privkey(), pos_integer(), non_neg_integer(), non_neg_integer(), pos_integer(), infinity | pos_integer(), {atom(), atom(), list()}) -> hbbft_data().
init(SK, N, F, J, BatchSize, MaxBuf, {M, Fn, A}) ->
    init(SK, N, F, J, BatchSize, MaxBuf, {M, Fn, A}, 0, []).

init(SK, N, F, J, BatchSize, MaxBuf, StampFun, Round, Buf) ->
    #hbbft_data{secret_key=SK,
                n=N, f=F, j=J,
                batch_size=BatchSize,
                acs=hbbft_acs:init(SK, N, F, J),
                round = Round,
                buf = Buf,
                max_buf=MaxBuf,
                stampfun=StampFun}.


-spec get_stamp_fun(hbbft_data()) -> {atom(), atom(), list()} | undefined.
get_stamp_fun(#hbbft_data{stampfun=S}) ->
    S.

-spec set_stamp_fun(atom(), atom(), list(), hbbft_data()) -> hbbft_data().
set_stamp_fun(M, F, A, Data) when is_atom(M), is_atom(F) ->
    Data#hbbft_data{stampfun={M, F, A}}.

%% start acs on demand
-spec start_on_demand(hbbft_data()) -> {hbbft_data(), already_started | {send, [rbc_wrapped_output()]}}.
start_on_demand(Data = #hbbft_data{buf=Buf, n=N, secret_key=SK, batch_size=BatchSize, acs_init=false}) ->
    %% pick proposed whichever is lesser from batchsize/n or buffer
    Proposed = hbbft_utils:random_n(min((BatchSize div N), length(Buf)), lists:sublist(Buf, BatchSize)),
    %% encrypt x -> tpke.enc(pk, proposed)
    Stamp = case Data#hbbft_data.stampfun of
                undefined -> undefined;
                {M, F, A} -> erlang:apply(M, F, A)
            end,
    EncX = encrypt(tpke_privkey:public_key(SK), term_to_binary({Stamp, Proposed})),
    %% time to kick off a round
    {NewACSState, {send, ACSResponse}} = hbbft_acs:input(Data#hbbft_data.acs, EncX),
    %% add this to acs set in data and send out the ACS response(s)
    {Data#hbbft_data{acs=NewACSState, acs_init=true},
     {send, hbbft_utils:wrap({acs, Data#hbbft_data.round}, ACSResponse)}};
start_on_demand(Data) ->
    {Data, already_started}.

%% someone submitting a transaction to the replica set
-spec input(hbbft_data(), binary()) -> {hbbft_data(), ok | {send, [rbc_wrapped_output()]} | full}.
input(Data = #hbbft_data{buf=Buf, max_buf=MaxBuf}, Txn) when length(Buf) < MaxBuf->
    %% add this txn to the the buffer
    NewBuf = [Txn | Buf],
    maybe_start_acs(Data#hbbft_data{buf=NewBuf});
input(Data = #hbbft_data{buf=_Buf}, _Txn) ->
    %% drop the txn
    {Data, full}.

%% The user has constructed something that looks like a block and is telling us which transactions
%% to remove from the buffer (accepted or invalid). Transactions missing causal context
%% (eg. a missing monotonic nonce prior to the current nonce) should remain in the buffer and thus
%% should not be placed in TransactionsToRemove. Once this returns, the user should call next_round/1.
-spec finalize_round(hbbft_data(), [binary()], binary()) -> {hbbft_data(), {send, [hbbft_utils:multicast(sign_msg())]}}.
finalize_round(Data, TransactionsToRemove, ThingToSign) ->
    NewBuf = lists:filter(fun(Item) ->
                                  not lists:member(Item, TransactionsToRemove)
                          end, Data#hbbft_data.buf),
    HashThing = tpke_pubkey:hash_message(tpke_privkey:public_key(Data#hbbft_data.secret_key), ThingToSign),
    BinShare = hbbft_utils:share_to_binary(tpke_privkey:sign(Data#hbbft_data.secret_key, HashThing)),
    %% multicast the signature to everyone
    {Data#hbbft_data{thingtosign=HashThing, buf=NewBuf}, {send, [{multicast, {sign, Data#hbbft_data.round, BinShare}}]}}.

%% does not require a signed message
-spec finalize_round(hbbft_data(), [binary()])-> hbbft_data().
finalize_round(Data, TransactionsToRemove) ->
    NewBuf = lists:filter(fun(Item) ->
                                  not lists:member(Item, TransactionsToRemove)
                          end, Data#hbbft_data.buf),
    Data#hbbft_data{buf=NewBuf}.

%% The user has obtained a signature and is ready to go to the next round
-spec next_round(hbbft_data()) -> {hbbft_data(), ok | {send, []}}.
next_round(Data = #hbbft_data{secret_key=SK, n=N, f=F, j=J}) ->
    %% reset all the round-dependant bits of the state and increment the round
    NewData = Data#hbbft_data{round=Data#hbbft_data.round + 1, acs=hbbft_acs:init(SK, N, F, J),
                              acs_init=false, acs_results=[],
                              sent_txns=false, sent_sig=false,
                              dec_shares=#{}, decrypted=#{},
                              sig_shares=#{}, thingtosign=undefined, stamps=[]},
    maybe_start_acs(NewData).

-spec next_round(hbbft_data(), pos_integer(), [binary()]) -> {hbbft_data(), ok | {send, []}}.
next_round(Data = #hbbft_data{secret_key=SK, n=N, f=F, j=J, buf=Buf}, NextRound, TransactionsToRemove) ->
    %% remove the request transactions
    NewBuf = lists:filter(fun(Item) ->
                                  not lists:member(Item, TransactionsToRemove)
                          end, Buf),
    %% reset all the round-dependant bits of the state and increment the round
    NewData = Data#hbbft_data{round=NextRound, acs=hbbft_acs:init(SK, N, F, J),
                              acs_init=false, acs_results=[],
                              sent_txns=false, sent_sig=false,
                              dec_shares=#{}, decrypted=#{}, buf=NewBuf,
                              sig_shares=#{}, thingtosign=undefined, stamps=[]},
    maybe_start_acs(NewData).

-spec round(hbbft_data()) -> non_neg_integer().
round(_Data=#hbbft_data{round=Round}) ->
    Round.

-spec buf(hbbft_data()) -> [binary()].
buf(_Data=#hbbft_data{buf = Buf}) ->
    Buf.

-spec buf([binary()], hbbft_data()) -> hbbft_data().
buf(Buf, Data) ->
    Data#hbbft_data{buf=Buf}.

-spec handle_msg(hbbft_data(), non_neg_integer(), acs_msg() | dec_msg() | sign_msg()) -> {hbbft_data(), ok |
                                                                                          defer |
                                                                                          {send, [hbbft_utils:multicast(dec_msg() |
                                                                                                                        sign_msg()) |
                                                                                                  rbc_wrapped_output() |
                                                                                                  bba_wrapped_output()]} |
                                                                                          {result, {transactions, list(), [binary()]}} |
                                                                                          {result, {signature, binary()}}} | ignore.
handle_msg(Data = #hbbft_data{round=R}, _J, {{acs, R2}, _ACSMsg}) when R2 > R ->
    %% ACS requested we defer this message for now
    {Data, defer};
handle_msg(Data = #hbbft_data{round=R}, J, {{acs, R}, ACSMsg}) ->
    %% ACS message for this round
    case hbbft_acs:handle_msg(Data#hbbft_data.acs, J, ACSMsg) of
        ignore -> ignore;
        {NewACS, ok} ->
            {Data#hbbft_data{acs=NewACS}, ok};
        {NewACS, {send, ACSResponse}} ->
            {Data#hbbft_data{acs=NewACS}, {send, hbbft_utils:wrap({acs, Data#hbbft_data.round}, ACSResponse)}};
        {NewACS, {result_and_send, Results, {send, ACSResponse}}} ->
            %% ACS[r] has returned, time to move on to the decrypt phase
            %% start decrypt phase
            Replies = lists:map(fun({I, Result}) ->
                                        EncKey = get_encrypted_key(Data#hbbft_data.secret_key, Result),
                                        Share = tpke_privkey:decrypt_share(Data#hbbft_data.secret_key, EncKey),
                                        SerializedShare = hbbft_utils:share_to_binary(Share),
                                        {multicast, {dec, Data#hbbft_data.round, I, SerializedShare}}
                                end, Results),
            %% verify any shares we received before we got the ACS result
            VerifiedShares = maps:map(fun({I, _}, {undefined, Share}) ->
                                              case lists:keyfind(I, 1, Results) of
                                                  {I, Enc} ->
                                                      EncKey = get_encrypted_key(Data#hbbft_data.secret_key, Enc),
                                                      Valid = tpke_pubkey:verify_share(tpke_privkey:public_key(Data#hbbft_data.secret_key), Share, EncKey),
                                                      {Valid, Share};
                                                  false ->
                                                      %% this is a share for an RBC we will never decode
                                                      {undefined, Share}
                                              end;
                                         (_, V) ->
                                              V
                                      end, Data#hbbft_data.dec_shares),
            {Data#hbbft_data{acs=NewACS, acs_results=Results, dec_shares=VerifiedShares}, {send,  hbbft_utils:wrap({acs, Data#hbbft_data.round}, ACSResponse) ++ Replies}};
        {NewACS, defer} ->
            {Data#hbbft_data{acs=NewACS}, defer}
    end;
handle_msg(Data = #hbbft_data{round=R}, _J, {dec, R2, _I, _Share}) when R2 > R ->
    {Data, defer};
handle_msg(Data = #hbbft_data{round=R}, J, {dec, R, I, Share}) ->
    %% check if we have enough to decode the bundle
    case maps:is_key(I, Data#hbbft_data.decrypted) %% have we already decrypted for this instance?
        orelse maps:is_key({I, J}, Data#hbbft_data.dec_shares) of %% do we already have this share?
        true ->
            %% we already have this share, or we've already decrypted this ACS result
            %% we don't need this
            ignore;
        false ->
            %% the Share now is a binary, deserialize it and then store in the dec_shares map
            DeserializedShare = hbbft_utils:binary_to_share(Share, Data#hbbft_data.secret_key),
            Valid = case lists:keyfind(I, 1, Data#hbbft_data.acs_results) of
                        {I, Enc0} ->
                            EncKey0 = get_encrypted_key(Data#hbbft_data.secret_key, Enc0),
                            tpke_pubkey:verify_share(tpke_privkey:public_key(Data#hbbft_data.secret_key), DeserializedShare, EncKey0);
                        false ->
                            %% the corresponding ACS has not yet returned so we can't verify the share yet
                            undefined
                    end,
            NewShares = maps:put({I, J}, {Valid, DeserializedShare}, Data#hbbft_data.dec_shares),
            SharesForThisBundle = [ S || {{Idx, _}, S} <- maps:to_list(NewShares), I == Idx],
            case lists:keymember(I, 1, Data#hbbft_data.acs_results)         %% was this instance included in the ACS result set?
                 andalso length(SharesForThisBundle) > Data#hbbft_data.f of %% do we have f+1 decryption shares?
                true ->
                  {I, Enc} = lists:keyfind(I, 1, Data#hbbft_data.acs_results),
                  EncKey = get_encrypted_key(Data#hbbft_data.secret_key, Enc),
                    case combine_shares(Data#hbbft_data.f, Data#hbbft_data.secret_key, SharesForThisBundle, EncKey) of
                        undefined ->
                            %% can't recover the key, consider this ACS failed if we have 2f+1 shares and still can't recover the key
                            case length(SharesForThisBundle) > 2 * Data#hbbft_data.f of
                                true ->
                                    %% ok, just declare this ACS returned an empty list
                                    NewDecrypted = maps:put(I, [], Data#hbbft_data.decrypted),
                                    check_completion(Data#hbbft_data{dec_shares=NewShares, decrypted=NewDecrypted});
                                false ->
                                    {Data#hbbft_data{dec_shares=NewShares}, ok}
                            end;
                        DecKey ->
                            case decrypt(DecKey, Enc) of
                                error ->
                                    %% can't decrypt, consider this ACS a failure
                                    %% just declare this ACS returned an empty list because we had
                                    %% f+1 valid shares but the resulting decryption key was unusuable to decrypt
                                    %% the transaction bundle
                                    NewDecrypted = maps:put(I, [], Data#hbbft_data.decrypted),
                                    check_completion(Data#hbbft_data{dec_shares=NewShares, decrypted=NewDecrypted});
                                Decrypted ->
                                    {Stamp, Transactions} = binary_to_term(Decrypted),
                                    NewDecrypted = maps:put(I, Transactions, Data#hbbft_data.decrypted),
                                    Stamps = [{I, Stamp} | Data#hbbft_data.stamps],
                                    check_completion(Data#hbbft_data{dec_shares=NewShares, decrypted=NewDecrypted, stamps=Stamps})
                            end
                    end;
                false ->
                    %% not enough shares yet
                    {Data#hbbft_data{dec_shares=NewShares}, ok}
            end
    end;
handle_msg(Data = #hbbft_data{round=R, thingtosign=ThingToSign}, _J, {sign, R2, _BinShare}) when ThingToSign == undefined  orelse R2 > R ->
    {Data, defer};
handle_msg(Data = #hbbft_data{round=R, thingtosign=ThingToSign}, J, {sign, R, BinShare}) when ThingToSign /= undefined ->
    %% messages related to signing the final block for this round, see finalize_round for more information
    %% Note: this is an extension to the HoneyBadger BFT specification
    Share = hbbft_utils:binary_to_share(BinShare, Data#hbbft_data.secret_key),
    %% verify the share
    PubKey = tpke_privkey:public_key(Data#hbbft_data.secret_key),
    case tpke_pubkey:verify_signature_share(PubKey, Share, ThingToSign) of
        true ->
            NewSigShares = maps:put(J, Share, Data#hbbft_data.sig_shares),
            %% check if we have at least f+1 shares
            case maps:size(NewSigShares) > Data#hbbft_data.f andalso not Data#hbbft_data.sent_sig of
                true ->
                    %% ok, we have enough people agreeing with us we can combine the signature shares
                    {ok, Sig} = tpke_pubkey:combine_verified_signature_shares(PubKey, maps:values(NewSigShares)),
                    case tpke_pubkey:verify_signature(PubKey, Sig, ThingToSign) of
                        true ->
                            %% verified signature, send the signature
                            {Data#hbbft_data{sig_shares=NewSigShares, sent_sig=true}, {result, {signature, erlang_pbc:element_to_binary(Sig)}}};
                        false ->
                            %% must have duplicate signature shares, keep waiting
                            {Data#hbbft_data{sig_shares=NewSigShares}, ok}
                    end;
                false ->
                    {Data#hbbft_data{sig_shares=NewSigShares}, ok}
            end;
        false ->
            ignore
    end;
handle_msg(_Data, _J, _Msg) ->
    ignore.

-spec maybe_start_acs(hbbft_data()) -> {hbbft_data(), ok | {send, [rbc_wrapped_output()]}}.
maybe_start_acs(Data = #hbbft_data{n=N, secret_key=SK, batch_size=BatchSize}) ->
    case length(Data#hbbft_data.buf) > BatchSize andalso Data#hbbft_data.acs_init == false of
        true ->
            %% compose a transaction bundle
            %% get the top b elements from buf
            %% pick a random B/N selection of them
            Proposed = hbbft_utils:random_n(BatchSize div N, lists:sublist(Data#hbbft_data.buf, length(Data#hbbft_data.buf) - BatchSize + 1, BatchSize)),
            %% encrypt x -> tpke.enc(pk, proposed)
            Stamp = case Data#hbbft_data.stampfun of
                undefined -> undefined;
                {M, F, A} -> erlang:apply(M, F, A)
            end,
            EncX = encrypt(tpke_privkey:public_key(SK), term_to_binary({Stamp, Proposed})),
            %% time to kick off a round
            {NewACSState, {send, ACSResponse}} = hbbft_acs:input(Data#hbbft_data.acs, EncX),
            %% add this to acs set in data and send out the ACS response(s)
            {Data#hbbft_data{acs=NewACSState, acs_init=true},
             {send, hbbft_utils:wrap({acs, Data#hbbft_data.round}, ACSResponse)}};
        false ->
            %% not enough transactions for this round yet
            {Data, ok}
    end.

-spec encrypt(tpke_pubkey:pubkey(), binary()) -> binary().
encrypt(PK, Bin) ->
    %% generate a random AES key and IV
    Key = crypto:strong_rand_bytes(32),
    IV = crypto:strong_rand_bytes(16),
    %% encrypt that random AES key with the HBBFT replica set's public key
    %% the result of the encryption is a 3-tuple that contains 2 PBC Elements and a 32 byte binary
    %% we need to encode all this crap into a binary value that we can unpack again sanely
    {U, V, W} = tpke_pubkey:encrypt(PK, Key),
    UBin = erlang_pbc:element_to_binary(U),
    WBin = erlang_pbc:element_to_binary(W),
    EncKey = <<(byte_size(UBin)):8/integer-unsigned, UBin/binary, V:32/binary, (byte_size(WBin)):8/integer-unsigned, WBin/binary>>,
    %% encrypt the bundle with AES-GCM and put the IV and the encrypted key in the Additional Authenticated Data (AAD)
    AAD = <<IV:16/binary, (byte_size(EncKey)):16/integer-unsigned, EncKey/binary>>,
    {CipherText, CipherTag} = crypto:block_encrypt(aes_gcm, Key, IV, {AAD, Bin}),
    %% assemble a final binary packet
    <<AAD/binary, CipherTag:16/binary, CipherText/binary>>.

-spec get_encrypted_key(tpke_privkey:privkey(), binary()) -> tpke_pubkey:ciphertext().
get_encrypted_key(SK, <<_IV:16/binary, EncKeySize:16/integer-unsigned, EncKey:EncKeySize/binary, _/binary>>) ->
    <<USize:8/integer-unsigned, UBin:USize/binary, V:32/binary, WSize:8/integer-unsigned, WBin:WSize/binary>> = EncKey,
    PubKey = tpke_privkey:public_key(SK),
    U = tpke_pubkey:deserialize_element(PubKey, UBin),
    W = tpke_pubkey:deserialize_element(PubKey, WBin),
    {U, V, W}.

-spec decrypt(binary(), binary()) -> binary() | error.
decrypt(Key, Bin) ->
    <<IV:16/binary, EncKeySize:16/integer-unsigned, EncKey:EncKeySize/binary, Tag:16/binary, CipherText/binary>> = Bin,
    crypto:block_decrypt(aes_gcm, Key, IV, {<<IV:16/binary, EncKeySize:16/integer-unsigned, EncKey:(EncKeySize)/binary>>, CipherText, Tag}).

-spec serialize(hbbft_data()) -> {hbbft_serialized_data(), tpke_privkey:privkey_serialized() | tpke_privkey:privkey()}.
serialize(Data) ->
    %% serialize the SK unless explicitly told not to
    serialize(Data, true).

-spec serialize(hbbft_data(), boolean()) -> {hbbft_serialized_data(), tpke_privkey:privkey_serialized() | tpke_privkey:privkey()}.
serialize(#hbbft_data{secret_key=SK}=Data, false) ->
    %% dont serialize the private key
    {serialize_hbbft_data(Data), SK};
serialize(#hbbft_data{secret_key=SK}=Data, true) ->
    %% serialize the private key as well
    {serialize_hbbft_data(Data), tpke_privkey:serialize(SK)}.

-spec deserialize(hbbft_serialized_data(), tpke_privkey:privkey()) -> hbbft_data().
deserialize(#hbbft_serialized_data{batch_size=BatchSize,
                                   n=N,
                                   f=F,
                                   j=J,
                                   round=Round,
                                   buf=Buf,
                                   max_buf=MaxBuf,
                                   acs=ACSData,
                                   acs_init=ACSInit,
                                   sent_txns=SentTxns,
                                   sent_sig=SentSig,
                                   acs_results=ACSResults,
                                   decrypted=Decrypted,
                                   sig_shares=SigShares,
                                   dec_shares=DecShares,
                                   thingtosign=ThingToSign,
                                   stampfun=Stampfun,
                                   stamps=Stamps}, SK) ->

    NewThingToSign = case ThingToSign of
                         undefined -> undefined;
                         _ -> tpke_pubkey:deserialize_element(tpke_privkey:public_key(SK), ThingToSign)
                     end,
    #hbbft_data{secret_key=SK,
                batch_size=BatchSize,
                n=N,
                f=F,
                j=J,
                round=Round,
                buf=Buf,
                max_buf=MaxBuf,
                acs=hbbft_acs:deserialize(ACSData, SK),
                acs_init=ACSInit,
                sent_txns=SentTxns,
                sent_sig=SentSig,
                acs_results=ACSResults,
                decrypted=Decrypted,
                dec_shares=maps:map(fun(_, {Valid, Share}) ->
                                            {Valid, hbbft_utils:binary_to_share(Share, SK)};
                                       ({I, _}, Share) ->
                                            %% compatability shim for old, untagged shares
                                            {I, Enc} = lists:keyfind(I, 1, ACSResults),
                                            EncKey = get_encrypted_key(SK, Enc),
                                            DeserializedShare = hbbft_utils:binary_to_share(Share, SK),
                                            Valid = tpke_pubkey:verify_share(tpke_privkey:public_key(SK), DeserializedShare, EncKey),
                                            {Valid, DeserializedShare}
                                    end, DecShares),
                sig_shares=maps:map(fun(_, Share) -> hbbft_utils:binary_to_share(Share, SK) end, SigShares),
                thingtosign=NewThingToSign,
                stampfun=Stampfun,
                stamps=Stamps}.

-spec serialize_hbbft_data(hbbft_data()) -> hbbft_serialized_data().
serialize_hbbft_data(#hbbft_data{batch_size=BatchSize,
                                 n=N,
                                 f=F,
                                 j=J,
                                 round=Round,
                                 buf=Buf,
                                 max_buf=MaxBuf,
                                 acs=ACSData,
                                 acs_init=ACSInit,
                                 sent_txns=SentTxns,
                                 sent_sig=SentSig,
                                 acs_results=ACSResults,
                                 dec_shares=DecShares,
                                 sig_shares=SigShares,
                                 decrypted=Decrypted,
                                 thingtosign=ThingToSign,
                                 stampfun=Stampfun,
                                 stamps=Stamps}) ->

    NewThingToSign = case ThingToSign of
                         undefined -> undefined;
                         _ -> erlang_pbc:element_to_binary(ThingToSign)
                     end,

    #hbbft_serialized_data{batch_size=BatchSize,
                           n=N,
                           f=F,
                           round=Round,
                           buf=Buf,
                           max_buf=MaxBuf,
                           acs=hbbft_acs:serialize(ACSData),
                           acs_init=ACSInit,
                           sent_txns=SentTxns,
                           decrypted=Decrypted,
                           j=J,
                           sent_sig=SentSig,
                           acs_results=ACSResults,
                           dec_shares=maps:map(fun(_, {Valid, Share}) -> {Valid, hbbft_utils:share_to_binary(Share)} end, DecShares),
                           sig_shares=maps:map(fun(_, V) -> hbbft_utils:share_to_binary(V) end, SigShares),
                           thingtosign=NewThingToSign,
                           stampfun=Stampfun,
                           stamps=Stamps}.

-spec is_serialized(hbbft_data() | hbbft_serialized_data()) -> boolean().
is_serialized(Data) when is_record(Data, hbbft_serialized_data) -> true;
is_serialized(Data) when is_record(Data, hbbft_data) -> false.

group_by(Tuples) ->
    group_by(Tuples, dict:new()).

group_by([], D) ->
    lists:keysort(1, [{K, lists:sort(V)} || {K, V} <- dict:to_list(D)]);
group_by([{K, V}|T], D) ->
    group_by(T, dict:append(K, V, D)).

check_completion(Data) ->
    case maps:size(Data#hbbft_data.decrypted) == length(Data#hbbft_data.acs_results) andalso not Data#hbbft_data.sent_txns of
        true ->
            %% we did it!
            %% Combine all unique messages into a single list
            TransactionsThisRound = lists:usort(lists:flatten(maps:values(Data#hbbft_data.decrypted))),
            StampsThisRound = lists:usort(Data#hbbft_data.stamps),
            %% return the transactions we agreed on to the user
            %% we have no idea which transactions are valid, invalid, out of order or missing
            %% causal context (eg. a nonce is not monotonic) so we return them to the user to let them
            %% figure it out. We expect the user to call finalize_round/3 once they've decided what they want to accept
            %% from this set of transactions.
            {Data#hbbft_data{sent_txns=true}, {result, {transactions, StampsThisRound, TransactionsThisRound}}};
        false ->
            {Data, ok}
    end.

-spec combine_shares(pos_integer(), tpke_privkey:privkey(), [tpke_privkey:share()], tpke_pubkey:ciphertext()) -> undefined | binary().
combine_shares(F, SK, SharesForThisBundle, EncKey) ->
    %% only use valid shares so an invalid share doesn't corrupt our result
    ValidSharesForThisBundle = [ S || {true, S} <- SharesForThisBundle ],
    case length(ValidSharesForThisBundle) > F of
        true ->
            tpke_pubkey:combine_shares(tpke_privkey:public_key(SK), EncKey, ValidSharesForThisBundle);
        false ->
            %% not enough valid shares to bother trying to combine them
            undefined
    end.
