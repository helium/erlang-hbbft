-module(common_coin).

-export([init/4, get_coin/1, share/3]).

-record(data, {
          state = waiting :: waiting | done,
          sk :: tpke_privkey:privkey(),
          sid :: undefined | binary(),
          n :: pos_integer(),
          f :: pos_integer(),
          shares = sets:new()
         }).

init(SecretKeyShard, Sid, N, F) ->
    {ok, #data{sk=SecretKeyShard, n=N, f=F, sid=Sid}}.

get_coin(Data = #data{state=done}) ->
    {Data, ok};
get_coin(Data) ->
    Share = tpke_privkey:sign(Data#data.sk, Data#data.sid),
    {Data, {send, [{multicast, {share, Share}}]}}.

share(Data = #data{state=done}, _J, _Share) ->
    {Data, ok};
share(Data, _J, Share) ->
    case tpke_pubkey:verify_signature_share(tpke_privkey:public_key(Data#data.sk), Share, Data#data.sid) of
        true ->
            NewData = Data#data{shares=sets:add_element(Share, Data#data.shares)},
            %% check if we have at least f+1 shares
            case sets:size(NewData#data.shares) > Data#data.f of
                true ->
                    %% combine shares
                    Sig = tpke_pubkey:combine_signature_shares(tpke_privkey:public_key(NewData#data.sk), sets:to_list(NewData#data.shares)),
                    %% check if the signature is valid
                    case tpke_pubkey:verify_signature(tpke_privkey:public_key(NewData#data.sk), Sig, NewData#data.sid) of
                        true ->
                            {NewData#data{state=done}, {result, erlang_pbc:element_to_binary(Sig)}};
                        false ->
                            {NewData, ok}
                    end;
                false ->
                    {NewData, ok}
            end;
        false ->
            %% XXX bad share can be proof of malfeasance
            {Data, ok}
    end.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

kill(Data) ->
    Data#data{state=done}.

init_test() ->
    N = 5,
    F = 1,
    dealer:start_link(N, F+1, 'SS512'),
    {ok, PubKey, PrivateKeys} = dealer:deal(),
    gen_server:stop(dealer),
    Sid = tpke_pubkey:hash_message(PubKey, crypto:strong_rand_bytes(32)),
    States = [element(2, common_coin:init(Sk, Sid, N, F)) || Sk <- PrivateKeys],
    StatesWithId = lists:zip(lists:seq(0, length(States) - 1), States),
    %% all valid members should call get_coin
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = get_coin(State),
                            {{J, NewState}, {J, Result}}
                    end, StatesWithId),
    {NewStates, Results} = lists:unzip(Res),
    ConvergedResults = do_send_outer(Results, NewStates, []),
    %% everyone should converge
    ?assertEqual(N, length(ConvergedResults)),
    ok.

one_dead_test() ->
    N = 5,
    F = 1,
    dealer:start_link(N, F+1, 'SS512'),
    {ok, PubKey, PrivateKeys} = dealer:deal(),
    gen_server:stop(dealer),
    Sid = tpke_pubkey:hash_message(PubKey, crypto:strong_rand_bytes(32)),
    [S0, S1, S2, S3, S4] = [element(2, common_coin:init(Sk, Sid, N, F)) || Sk <- PrivateKeys],
    StatesWithId = lists:zip(lists:seq(0, N - 1), [S0, S1, kill(S2), S3, S4]),
    %% all valid members should call get_coin
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = get_coin(State),
                            {{J, NewState}, {J, Result}}
                    end, StatesWithId),
    {NewStates, Results} = lists:unzip(Res),
    ConvergedResults = do_send_outer(Results, NewStates, []),
    %% everyone but one should converge
    ?assertEqual(N - 1, length(ConvergedResults)),
    %% everyone should have the same value
    DistinctResults = lists:usort([ Sig || {result, {_J, Sig}} <- ConvergedResults ]),
    ?assertEqual(1, length(DistinctResults)),
    ok.

two_dead_test() ->
    N = 5,
    F = 1,
    dealer:start_link(N, F+1, 'SS512'),
    {ok, PubKey, PrivateKeys} = dealer:deal(),
    gen_server:stop(dealer),
    Sid = tpke_pubkey:hash_message(PubKey, crypto:strong_rand_bytes(32)),
    [S0, S1, S2, S3, S4] = [element(2, common_coin:init(Sk, Sid, N, F)) || Sk <- PrivateKeys],
    StatesWithId = lists:zip(lists:seq(0, N - 1), [S0, S1, kill(S2), S3, kill(S4)]),
    %% all valid members should call get_coin
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = get_coin(State),
                            {{J, NewState}, {J, Result}}
                    end, StatesWithId),
    {NewStates, Results} = lists:unzip(Res),
    ConvergedResults = do_send_outer(Results, NewStates, []),
    %% everyone but two should converge
    ?assertEqual(N - 2, length(ConvergedResults)),
    %% everyone should have the same value
    DistinctResults = lists:usort([ Sig || {result, {_J, Sig}} <- ConvergedResults ]),
    ?assertEqual(1, length(DistinctResults)),
    ok.

too_many_dead_test() ->
    N = 5,
    F = 4,
    dealer:start_link(N, F+1, 'SS512'),
    {ok, PubKey, PrivateKeys} = dealer:deal(),
    gen_server:stop(dealer),
    Sid = tpke_pubkey:hash_message(PubKey, crypto:strong_rand_bytes(32)),
    [S0, S1, S2, S3, S4] = [element(2, common_coin:init(Sk, Sid, N, F)) || Sk <- PrivateKeys],
    StatesWithId = lists:zip(lists:seq(0, N - 1), [S0, S1, kill(S2), S3, kill(S4)]),
    %% all valid members should call get_coin
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = get_coin(State),
                            {{J, NewState}, {J, Result}}
                    end, StatesWithId),
    {NewStates, Results} = lists:unzip(Res),
    ConvergedResults = do_send_outer(Results, NewStates, []),
    %% nobody should converge
    ?assertEqual(0, length(ConvergedResults)),
    ok.

key_mismatch_f1_test() ->
    N = 5,
    F = 1,
    dealer:start_link(N, F+1, 'SS512'),
    {ok, PubKey, PrivateKeys} = dealer:deal(),
    {ok, _, PrivateKeys2} = dealer:deal(),
    gen_server:stop(dealer),
    Sid = tpke_pubkey:hash_message(PubKey, crypto:strong_rand_bytes(32)),
    [S0, S1, S2, S3, S4] = [element(2, common_coin:init(Sk, Sid, N, F)) || Sk <- lists:sublist(PrivateKeys, 3) ++ lists:sublist(PrivateKeys2, 2)],
    StatesWithId = lists:zip(lists:seq(0, N - 1), [S0, S1, S2, S3, S4]),
    %% all valid members should call get_coin
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = get_coin(State),
                            {{J, NewState}, {J, Result}}
                    end, StatesWithId),
    {NewStates, Results} = lists:unzip(Res),
    ConvergedResults = do_send_outer(Results, NewStates, []),
    io:format("Results ~p~n", [ConvergedResults]),
    %% all 5 should converge, but there should be 2 distinct results
    ?assertEqual(5, length(ConvergedResults)),
    DistinctResults = lists:usort([ Sig || {result, {_J, Sig}} <- ConvergedResults ]),
    ?assertEqual(2, length(DistinctResults)),
    ok.


key_mismatch_f2_test() ->
    N = 5,
    F = 2,
    dealer:start_link(N, F+1, 'SS512'),
    {ok, PubKey, PrivateKeys} = dealer:deal(),
    {ok, _, PrivateKeys2} = dealer:deal(),
    gen_server:stop(dealer),
    Sid = tpke_pubkey:hash_message(PubKey, crypto:strong_rand_bytes(32)),
    [S0, S1, S2, S3, S4] = [element(2, common_coin:init(Sk, Sid, N, F)) || Sk <- lists:sublist(PrivateKeys, 3) ++ lists:sublist(PrivateKeys2, 2)],
    StatesWithId = lists:zip(lists:seq(0, N - 1), [S0, S1, S2, S3, S4]),
    %% all valid members should call get_coin
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = get_coin(State),
                            {{J, NewState}, {J, Result}}
                    end, StatesWithId),
    {NewStates, Results} = lists:unzip(Res),
    ConvergedResults = do_send_outer(Results, NewStates, []),
    io:format("Results ~p~n", [ConvergedResults]),
    %% the 3 with the right keys should converge to the same value
    ?assertEqual(3, length(ConvergedResults)),
    DistinctResults = lists:usort([ Sig || {result, {_J, Sig}} <- ConvergedResults ]),
    ?assertEqual(1, length(DistinctResults)),
    ok.



do_send_outer([], _, Acc) ->
    Acc;
do_send_outer([{result, {Id, Result}} | T], Pids, Acc) ->
    do_send_outer(T, Pids, [{result, {Id, Result}} | Acc]);
do_send_outer([H|T], States, Acc) ->
    {R, NewStates} = do_send(H, [], States),
    do_send_outer(T++R, NewStates, Acc).

do_send({Id, {result, Result}}, Acc, States) ->
    {[{result, {Id, Result}} | Acc], States};
do_send({_, ok}, Acc, States) ->
    {Acc, States};
do_send({_, {send, []}}, Acc, States) ->
    {Acc, States};
do_send({Id, {send, [{multicast, Msg}|T]}}, Acc, States) ->
    case Msg of
        {share, S} ->
            Res = lists:map(fun({J, State}) ->
                                    {NewState, Result} = share(State, Id, S),
                                    {{J, NewState}, {J, Result}}
                            end, States),
            {NewStates, Results} = lists:unzip(Res),
            do_send({Id, {send, T}}, Results ++ Acc, lists:ukeymerge(1, NewStates, States))
    end.

-endif.


