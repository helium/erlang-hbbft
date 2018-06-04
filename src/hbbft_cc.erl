-module(hbbft_cc).

-export([init/4, get_coin/1, handle_msg/3, serialize/1, deserialize/2]).

-record(cc_data, {
          state = waiting :: waiting | done,
          sk :: tpke_privkey:privkey(),
          %% Note: sid is assumed to be a unique nonce that serves as name of this common coin
          sid :: erlang_pbc:element(),
          n :: pos_integer(),
          f :: non_neg_integer(),
          shares = maps:new() :: #{non_neg_integer() => tpke_privkey:share()}
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

%% Figure12. Bullet1
%% Trusted Setup Phase: A trusted dealer runs pk, {ski } ←
%% ThresholdSetup to generate a common public key, as well as
%% secret key shares {ski }, one for each party (secret key ski is
%% distributed to party Pi). Note that a single setup can be used to
%% support a family of Coins indexed by arbitrary sid strings.
-spec init(tpke_privkey:privkey(), binary() | erlang_pbc:element(), pos_integer(), non_neg_integer()) -> cc_data().
init(SecretKeyShard, Bin, N, F) when is_binary(Bin) ->
    Sid = tpke_pubkey:hash_message(tpke_privkey:public_key(SecretKeyShard), Bin),
    init(SecretKeyShard, Sid, N, F);
init(SecretKeyShard, Sid, N, F) ->
    #cc_data{sk=SecretKeyShard, n=N, f=F, sid=Sid}.


%% Figure12. Bullet2
%% on input GetCoin, multicast ThresholdSignpk (ski, sid)
-spec get_coin(cc_data()) -> {cc_data(), ok | {send, [hbbft_utils:multicast(share_msg())]}}.
get_coin(Data = #cc_data{state=done}) ->
    {Data, ok};
get_coin(Data) ->
    Share = tpke_privkey:sign(Data#cc_data.sk, Data#cc_data.sid),
    SerializedShare = hbbft_utils:share_to_binary(Share),
    {Data, {send, [{multicast, {share, SerializedShare}}]}}.


%% upon receiving at least f + 1 shares, attempt to combine them
%% into a signature:
%% sig ← ThresholdCombinepk ({ j, s j })
%% if ThresholdVerifypk(sid) then deliver sig
%% TODO: more specific return type than an integer?
-spec handle_msg(cc_data(), non_neg_integer(), share_msg()) -> {cc_data(), ok | {result, integer()}}.
handle_msg(Data, J, {share, Share}) ->
    share(Data, J, Share).

%% TODO: more specific return type than an integer?
-spec share(cc_data(), non_neg_integer(), binary()) -> {cc_data(), ok | {result, integer()}}.
share(Data = #cc_data{state=done}, _J, _Share) ->
    {Data, ok};
share(Data, J, Share) ->
    case maps:is_key(J, Data#cc_data.shares) of
        false ->
            %% store the deserialized share in the shares map, convenient to use later to verify signature
            DeserializedShare = hbbft_utils:binary_to_share(Share, Data#cc_data.sk),
            case tpke_pubkey:verify_signature_share(tpke_privkey:public_key(Data#cc_data.sk), DeserializedShare, Data#cc_data.sid) of
                true ->
                    NewData = Data#cc_data{shares=maps:put(J, DeserializedShare, Data#cc_data.shares)},
                    %% check if we have at least f+1 shares
                    case maps:size(NewData#cc_data.shares) > Data#cc_data.f of
                        true ->
                            %% combine shares
                            {ok, Sig} = tpke_pubkey:combine_signature_shares(tpke_privkey:public_key(NewData#cc_data.sk), maps:values(NewData#cc_data.shares), Data#cc_data.sid),
                            %% check if the signature is valid
                            case tpke_pubkey:verify_signature(tpke_privkey:public_key(NewData#cc_data.sk), Sig, NewData#cc_data.sid) of
                                true ->
                                    %% TODO do something better here!
                                    <<Val:32/integer, _/binary>> = erlang_pbc:element_to_binary(Sig),
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
            {Data, ok}
    end.

-spec serialize(cc_data()) -> cc_serialized_data().
serialize(#cc_data{state=State, sid=SID, n=N, f=F, shares=Shares}) ->
    #cc_serialized_data{state=State, sid=erlang_pbc:element_to_binary(SID), n=N, f=F, shares=serialize_shares(Shares)}.

-spec deserialize(cc_serialized_data(), tpke_privkey:privkey()) -> cc_data().
deserialize(#cc_serialized_data{state=State, sid=SID, n=N, f=F, shares=Shares}, SK) ->
    Element = tpke_pubkey:deserialize_element(tpke_privkey:public_key(SK), SID),
    #cc_data{state=State, sk=SK, sid=Element, n=N, f=F, shares=deserialize_shares(Shares, SK)}.

-spec serialize_shares(#{non_neg_integer() => tpke_privkey:share()}) -> #{non_neg_integer() => binary()}.
serialize_shares(Shares) ->
    maps:map(fun(_K, V) -> hbbft_utils:share_to_binary(V) end, Shares).

-spec deserialize_shares(#{non_neg_integer() => binary()}, tpke_privkey:privkey()) -> #{non_neg_integer() => tpke_privkey:share()}.
deserialize_shares(Shares, SK) ->
    maps:map(fun(_K, V) -> hbbft_utils:binary_to_share(V, SK) end, Shares).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

init_test() ->
    N = 5,
    F = 1,
    {ok, Dealer} = dealer:start_link(N, F+1, 'SS512'),
    {ok, PubKey, PrivateKeys} = dealer:deal(Dealer),
    gen_server:stop(Dealer),
    Sid = tpke_pubkey:hash_message(PubKey, crypto:strong_rand_bytes(32)),
    States = [hbbft_cc:init(Sk, Sid, N, F) || Sk <- PrivateKeys],
    StatesWithId = lists:zip(lists:seq(0, length(States) - 1), States),
    %% all valid members should call get_coin
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = get_coin(State),
                            {{J, NewState}, {J, Result}}
                    end, StatesWithId),
    {NewStates, Results} = lists:unzip(Res),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(?MODULE, Results, NewStates, sets:new()),
    %% everyone should converge
    ?assertEqual(N, sets:size(ConvergedResults)),
    ok.

one_dead_test() ->
    N = 5,
    F = 1,
    {ok, Dealer} = dealer:start_link(N, F+1, 'SS512'),
    {ok, PubKey, PrivateKeys} = dealer:deal(Dealer),
    gen_server:stop(Dealer),
    Sid = tpke_pubkey:hash_message(PubKey, crypto:strong_rand_bytes(32)),
    [S0, S1, _S2, S3, S4] = [hbbft_cc:init(Sk, Sid, N, F) || Sk <- PrivateKeys],
    StatesWithId = lists:zip(lists:seq(0, N - 2), [S0, S1, S3, S4]),
    %% all valid members should call get_coin
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = get_coin(State),
                            {{J, NewState}, {J, Result}}
                    end, StatesWithId),
    {NewStates, Results} = lists:unzip(Res),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(?MODULE, Results, NewStates, sets:new()),
    %% everyone but one should converge
    ?assertEqual(N - 1, sets:size(ConvergedResults)),
    %% everyone should have the same value
    DistinctResults = lists:usort([ Sig || {result, {_J, Sig}} <- sets:to_list(ConvergedResults) ]),
    ?assertEqual(1, length(DistinctResults)),
    ok.

two_dead_test() ->
    N = 5,
    F = 1,
    {ok, Dealer} = dealer:start_link(N, F+1, 'SS512'),
    {ok, PubKey, PrivateKeys} = dealer:deal(Dealer),
    gen_server:stop(Dealer),
    Sid = tpke_pubkey:hash_message(PubKey, crypto:strong_rand_bytes(32)),
    [S0, S1, _S2, S3, _S4] = [hbbft_cc:init(Sk, Sid, N, F) || Sk <- PrivateKeys],
    StatesWithId = lists:zip(lists:seq(0, N - 3), [S0, S1, S3]),
    %% all valid members should call get_coin
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = get_coin(State),
                            {{J, NewState}, {J, Result}}
                    end, StatesWithId),
    {NewStates, Results} = lists:unzip(Res),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(?MODULE, Results, NewStates, sets:new()),
    %% everyone but two should converge
    ?assertEqual(N - 2, sets:size(ConvergedResults)),
    %% everyone should have the same value
    DistinctResults = lists:usort([ Sig || {result, {_J, Sig}} <- sets:to_list(ConvergedResults) ]),
    ?assertEqual(1, length(DistinctResults)),
    ok.

too_many_dead_test() ->
    N = 5,
    F = 4,
    {ok, Dealer} = dealer:start_link(N, F+1, 'SS512'),
    {ok, PubKey, PrivateKeys} = dealer:deal(Dealer),
    gen_server:stop(Dealer),
    Sid = tpke_pubkey:hash_message(PubKey, crypto:strong_rand_bytes(32)),
    [S0, S1, _S2, S3, _S4] = [hbbft_cc:init(Sk, Sid, N, F) || Sk <- PrivateKeys],
    StatesWithId = lists:zip(lists:seq(0, N - 3), [S0, S1, S3]),
    %% all valid members should call get_coin
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = get_coin(State),
                            {{J, NewState}, {J, Result}}
                    end, StatesWithId),
    {NewStates, Results} = lists:unzip(Res),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(?MODULE, Results, NewStates, sets:new()),
    %% nobody should converge
    ?assertEqual(0, sets:size(ConvergedResults)),
    ok.

key_mismatch_f1_test() ->
    N = 5,
    F = 1,
    {ok, Dealer} = dealer:start_link(N, F+1, 'SS512'),
    {ok, PubKey, PrivateKeys} = dealer:deal(Dealer),
    {ok, _, PrivateKeys2} = dealer:deal(Dealer),
    gen_server:stop(Dealer),
    Sid = tpke_pubkey:hash_message(PubKey, crypto:strong_rand_bytes(32)),
    [S0, S1, S2, S3, S4] = [hbbft_cc:init(Sk, Sid, N, F) || Sk <- lists:sublist(PrivateKeys, 3) ++ lists:sublist(PrivateKeys2, 2)],
    StatesWithId = lists:zip(lists:seq(0, N - 1), [S0, S1, S2, S3, S4]),
    %% all valid members should call get_coin
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = get_coin(State),
                            {{J, NewState}, {J, Result}}
                    end, StatesWithId),
    {NewStates, Results} = lists:unzip(Res),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(?MODULE, Results, NewStates, sets:new()),
    %% all 5 should converge, but there should be 2 distinct results
    ?assertEqual(5, sets:size(ConvergedResults)),
    DistinctResults = lists:usort([ Sig || {result, {_J, Sig}} <- sets:to_list(ConvergedResults) ]),
    ?assertEqual(2, length(DistinctResults)),
    ok.


key_mismatch_f2_test() ->
    N = 5,
    F = 2,
    {ok, Dealer} = dealer:start_link(N, F+1, 'SS512'),
    {ok, PubKey, PrivateKeys} = dealer:deal(Dealer),
    {ok, _, PrivateKeys2} = dealer:deal(Dealer),
    gen_server:stop(Dealer),
    Sid = tpke_pubkey:hash_message(PubKey, crypto:strong_rand_bytes(32)),
    [S0, S1, S2, S3, S4] = [hbbft_cc:init(Sk, Sid, N, F) || Sk <- lists:sublist(PrivateKeys, 3) ++ lists:sublist(PrivateKeys2, 2)],
    StatesWithId = lists:zip(lists:seq(0, N - 1), [S0, S1, S2, S3, S4]),
    %% all valid members should call get_coin
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = get_coin(State),
                            {{J, NewState}, {J, Result}}
                    end, StatesWithId),
    {NewStates, Results} = lists:unzip(Res),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(?MODULE, Results, NewStates, sets:new()),
    %% the 3 with the right keys should converge to the same value
    ?assertEqual(3, sets:size(ConvergedResults)),
    DistinctResults = lists:usort([ Sig || {result, {_J, Sig}} <- sets:to_list(ConvergedResults) ]),
    ?assertEqual(1, length(DistinctResults)),
    ok.

mixed_keys_test() ->
    N = 5,
    F = 1,
    {ok, Dealer} = dealer:start_link(N, F+1, 'SS512'),
    {ok, PubKey, PrivateKeys} = dealer:deal(Dealer),
    {ok, _, PrivateKeys2} = dealer:deal(Dealer),
    gen_server:stop(Dealer),

    Sid = tpke_pubkey:hash_message(PubKey, crypto:strong_rand_bytes(32)),

    [S0, S1, S2, _, _] = [hbbft_cc:init(Sk, Sid, N, F) || Sk <- PrivateKeys],
    [_, _, _, S3, S4] = [hbbft_cc:init(Sk, Sid, N, F) || Sk <- PrivateKeys2],

    StatesWithId = lists:zip(lists:seq(0, N - 1), [S0, S1, S2, S3, S4]),
    %% all valid members should call get_coin
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = get_coin(State),
                            {{J, NewState}, {J, Result}}
                    end, StatesWithId),
    {NewStates, Results} = lists:unzip(Res),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(?MODULE, Results, NewStates, sets:new()),

    DistinctCoins = sets:from_list([Coin || {result, {_, Coin}} <- sets:to_list(ConvergedResults)]),
    %% two distinct sets have converged with different coins each
    ?assertEqual(2, sets:size(DistinctCoins)),

    %% everyone but two should converge
    ?assertEqual(N, sets:size(ConvergedResults)),
    ok.
-endif.
