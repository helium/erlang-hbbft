-module(common_coin).

-export([init/4, get_coin/1, handle_msg/3]).

-record(data, {
          state = waiting :: waiting | done,
          sk :: tpke_privkey:privkey(),
          sid :: undefined | binary(),
          n :: pos_integer(),
          f :: pos_integer(),
          shares = sets:new()
         }).

init(SecretKeyShard, Bin, N, F) when is_binary(Bin) ->
    Sid = tpke_pubkey:hash_message(tpke_privkey:public_key(SecretKeyShard), Bin),
    init(SecretKeyShard, Sid, N, F);
init(SecretKeyShard, Sid, N, F) ->
    #data{sk=SecretKeyShard, n=N, f=F, sid=Sid}.

get_coin(Data = #data{state=done}) ->
    {Data, ok};
get_coin(Data) ->
    Share = tpke_privkey:sign(Data#data.sk, Data#data.sid),
    {Data, {send, [{multicast, {share, Share}}]}}.

handle_msg(Data, J, {share, Share}) ->
    share(Data, J, Share).

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
                            <<Val:32/integer, _/binary>> = erlang_pbc:element_to_binary(Sig),
                            {NewData#data{state=done}, {result, Val}};
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
    States = [common_coin:init(Sk, Sid, N, F) || Sk <- PrivateKeys],
    StatesWithId = lists:zip(lists:seq(0, length(States) - 1), States),
    %% all valid members should call get_coin
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = get_coin(State),
                            {{J, NewState}, {J, Result}}
                    end, StatesWithId),
    {NewStates, Results} = lists:unzip(Res),
    ConvergedResults = do_send_outer(Results, NewStates, sets:new()),
    %% everyone should converge
    ?assertEqual(N, sets:size(ConvergedResults)),
    ok.

one_dead_test() ->
    N = 5,
    F = 1,
    dealer:start_link(N, F+1, 'SS512'),
    {ok, PubKey, PrivateKeys} = dealer:deal(),
    gen_server:stop(dealer),
    Sid = tpke_pubkey:hash_message(PubKey, crypto:strong_rand_bytes(32)),
    [S0, S1, S2, S3, S4] = [common_coin:init(Sk, Sid, N, F) || Sk <- PrivateKeys],
    StatesWithId = lists:zip(lists:seq(0, N - 1), [S0, S1, kill(S2), S3, S4]),
    %% all valid members should call get_coin
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = get_coin(State),
                            {{J, NewState}, {J, Result}}
                    end, StatesWithId),
    {NewStates, Results} = lists:unzip(Res),
    ConvergedResults = do_send_outer(Results, NewStates, sets:new()),
    %% everyone but one should converge
    ?assertEqual(N - 1, sets:size(ConvergedResults)),
    ok.

two_dead_test() ->
    N = 5,
    F = 1,
    dealer:start_link(N, F+1, 'SS512'),
    {ok, PubKey, PrivateKeys} = dealer:deal(),
    gen_server:stop(dealer),
    Sid = tpke_pubkey:hash_message(PubKey, crypto:strong_rand_bytes(32)),
    [S0, S1, S2, S3, S4] = [common_coin:init(Sk, Sid, N, F) || Sk <- PrivateKeys],
    StatesWithId = lists:zip(lists:seq(0, N - 1), [S0, S1, kill(S2), S3, kill(S4)]),
    %% all valid members should call get_coin
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = get_coin(State),
                            {{J, NewState}, {J, Result}}
                    end, StatesWithId),
    {NewStates, Results} = lists:unzip(Res),
    ConvergedResults = do_send_outer(Results, NewStates, sets:new()),
    %% everyone but two should converge
    ?assertEqual(N - 2, sets:size(ConvergedResults)),
    ok.

too_many_dead_test() ->
    N = 5,
    F = 4,
    dealer:start_link(N, F+1, 'SS512'),
    {ok, PubKey, PrivateKeys} = dealer:deal(),
    gen_server:stop(dealer),
    Sid = tpke_pubkey:hash_message(PubKey, crypto:strong_rand_bytes(32)),
    [S0, S1, S2, S3, S4] = [common_coin:init(Sk, Sid, N, F) || Sk <- PrivateKeys],
    StatesWithId = lists:zip(lists:seq(0, N - 1), [S0, S1, kill(S2), S3, kill(S4)]),
    %% all valid members should call get_coin
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = get_coin(State),
                            {{J, NewState}, {J, Result}}
                    end, StatesWithId),
    {NewStates, Results} = lists:unzip(Res),
    ConvergedResults = do_send_outer(Results, NewStates, sets:new()),
    %% nobody should converge
    ?assertEqual(0, sets:size(ConvergedResults)),
    ok.

mixed_keys_test() ->
    N = 5,
    F = 1,
    dealer:start_link(N, F+1, 'SS512'),
    {ok, PubKey, PrivateKeys} = dealer:deal(),
    {ok, PubKey2, PrivateKeys2} = dealer:deal(),

    gen_server:stop(dealer),

    Sid = tpke_pubkey:hash_message(PubKey, crypto:strong_rand_bytes(32)),

    [S0, S1, S2, _, _] = [common_coin:init(Sk, Sid, N, F) || Sk <- PrivateKeys],
    [_, _, _, S3, S4] = [common_coin:init(Sk, Sid, N, F) || Sk <- PrivateKeys2],

    StatesWithId = lists:zip(lists:seq(0, N - 1), [S0, S1, S2, S3, S4]),
    %% all valid members should call get_coin
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = get_coin(State),
                            {{J, NewState}, {J, Result}}
                    end, StatesWithId),
    {NewStates, Results} = lists:unzip(Res),
    ConvergedResults = do_send_outer(Results, NewStates, sets:new()),

    DistinctCoins = sets:from_list([Coin || {result, {_, Coin}} <- sets:to_list(ConvergedResults)]),
    io:format("DistinctCoins: ~p~n", [sets:to_list(DistinctCoins)]),
    %% two distinct sets have converged with different coins each
    ?assertEqual(2, sets:size(DistinctCoins)),

    %% io:format("ConvergedResults: ~p~n", [sets:to_list(ConvergedResults)]),
    %% everyone but two should converge
    ?assertEqual(N, sets:size(ConvergedResults)),
    ok.

do_send_outer([], _, Acc) ->
    Acc;
do_send_outer([{result, {Id, Result}} | T], Pids, Acc) ->
    do_send_outer(T, Pids, sets:add_element({result, {Id, Result}}, Acc));
do_send_outer([H|T], States, Acc) ->
    {R, NewStates} = do_send(H, [], States),
    do_send_outer(T++R, NewStates, Acc).

do_send({Id, {result, Result}}, Acc, States) ->
    {[{result, {Id, Result}} | Acc], States};
do_send({_, ok}, Acc, States) ->
    {Acc, States};
do_send({_, {send, []}}, Acc, States) ->
    {Acc, States};
do_send({Id, {send, [{unicast, J, Msg}|T]}}, Acc, States) ->
    {J, State} = lists:keyfind(J, 1, States),
    {NewState, Result} = handle_msg(State, Id, Msg),
    do_send({Id, {send, T}}, [{J, Result}|Acc], lists:keyreplace(J, 1, States, {J, NewState}));
do_send({Id, {send, [{multicast, Msg}|T]}}, Acc, States) ->
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = handle_msg(State, Id, Msg),
                            {{J, NewState}, {J, Result}}
                    end, States),
    {NewStates, Results} = lists:unzip(Res),
    do_send({Id, {send, T}}, Results ++ Acc, lists:ukeymerge(1, NewStates, States)).
-endif.
