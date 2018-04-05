-module(common_coin).

-export([init/4, get_coin/1, share/3]).

-record(data, {
          state = waiting :: waiting | done,
          sk :: tpke_privkey:privkey(),
          sid :: undefined | binary(),
          n :: pos_integer(),
          f :: pos_integer(),
          shares = []
         }).

init(SecretKeyShard, Sid, N, F) ->
    {ok, #data{sk=SecretKeyShard, n=N, f=F, sid=Sid}}.

get_coin(Data = #data{state=done}) ->
    {Data, ok};
get_coin(Data) ->
    Share = tpke_privkey:sign(Data#data.sk, Data#data.sid),
    {Data, {send, [{multicast, {share, Share}}]}}.

share(Data = #data{state=done}, _J, Share) ->
    {Data, ok};
share(Data, _J, Share) ->
    case tpke_pubkey:verify_signature_share(tpke_privkey:public_key(Data#data.sk), Share, Data#data.sid) of
        true ->
            NewData = Data#data{shares=lists:usort([Share|Data#data.shares])},
            %% check if we have at least f+1 shares
            case length(NewData#data.shares) > Data#data.f of
                true ->
                    Sig = tpke_pubkey:combine_signature_shares(tpke_privkey:public_key(NewData#data.sk), NewData#data.shares),
                    {NewData#data{state=done}, {result, Sig}};
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


