-module(hbbft_cc_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, init_per_testcase/2, end_per_testcase/2]).
-export([
         init_test/1,
         one_dead_test/1,
         two_dead_test/1,
         too_many_dead_test/1,
         key_mismatch_f1_test/1,
         key_mismatch_f2_test/1,
         mixed_keys_test/1
        ]).

all() ->
    [
     init_test,
     one_dead_test,
     two_dead_test,
     too_many_dead_test,
     key_mismatch_f1_test,
     key_mismatch_f2_test,
     mixed_keys_test
    ].

init_per_testcase(_, Config) ->
    N = 5,
    F = N div 4,
    Module = hbbft_cc,
    {ok, Dealer} = dealer:start_link(N, F+1, 'SS512'),
    {ok, PubKey, PrivateKeys} = dealer:deal(Dealer),
    [{n, N}, {f, F}, {dealer, Dealer}, {module, Module}, {pubkey, PubKey}, {privatekeys, PrivateKeys} | Config].

end_per_testcase(_, Config) ->
    Dealer = proplists:get_value(dealer, Config, undefined),
    case Dealer of
        undefined -> ok;
        Pid ->
            gen_server:stop(Pid)
    end.

init_test(Config) ->
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config),
    Module = proplists:get_value(module, Config),
    PubKey = proplists:get_value(pubkey, Config),
    PrivateKeys = proplists:get_value(privatekeys, Config),
    Sid = tpke_pubkey:hash_message(PubKey, crypto:strong_rand_bytes(32)),
    States = [hbbft_cc:init(Sk, Sid, N, F) || Sk <- PrivateKeys],
    StatesWithId = lists:zip(lists:seq(0, length(States) - 1), States),
    %% all valid members should call get_coin
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = hbbft_cc:get_coin(State),
                            {{J, NewState}, {J, Result}}
                    end, StatesWithId),
    {NewStates, Results} = lists:unzip(Res),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(Module, Results, NewStates, sets:new()),
    ConvergedResultsList = sets:to_list(ConvergedResults),
    ct:pal("ConvergedResultsList: ~p~n", [ConvergedResultsList]),
    %% everyone should converge
    ?assertEqual(N, sets:size(ConvergedResults)),
    ok.

one_dead_test(Config) ->
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config),
    Module = proplists:get_value(module, Config),
    PubKey = proplists:get_value(pubkey, Config),
    PrivateKeys = proplists:get_value(privatekeys, Config),
    Sid = tpke_pubkey:hash_message(PubKey, crypto:strong_rand_bytes(32)),
    [S0, S1, _S2, S3, S4] = [hbbft_cc:init(Sk, Sid, N, F) || Sk <- PrivateKeys],
    StatesWithId = lists:zip(lists:seq(0, N - 2), [S0, S1, S3, S4]),
    %% all valid members should call get_coin
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = hbbft_cc:get_coin(State),
                            {{J, NewState}, {J, Result}}
                    end, StatesWithId),
    {NewStates, Results} = lists:unzip(Res),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(Module, Results, NewStates, sets:new()),
    ConvergedResultsList = sets:to_list(ConvergedResults),
    ct:pal("ConvergedResultsList: ~p~n", [ConvergedResultsList]),
    %% everyone but one should converge
    ?assertEqual(N - 1, sets:size(ConvergedResults)),
    %% everyone should have the same value
    DistinctResults = lists:usort([ Sig || {result, {_J, Sig}} <- sets:to_list(ConvergedResults) ]),
    ?assertEqual(1, length(DistinctResults)),
    ok.

two_dead_test(Config) ->
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config),
    Module = proplists:get_value(module, Config),
    PubKey = proplists:get_value(pubkey, Config),
    PrivateKeys = proplists:get_value(privatekeys, Config),
    Sid = tpke_pubkey:hash_message(PubKey, crypto:strong_rand_bytes(32)),
    [S0, S1, _S2, S3, _S4] = [hbbft_cc:init(Sk, Sid, N, F) || Sk <- PrivateKeys],
    StatesWithId = lists:zip(lists:seq(0, N - 3), [S0, S1, S3]),
    %% all valid members should call get_coin
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = hbbft_cc:get_coin(State),
                            {{J, NewState}, {J, Result}}
                    end, StatesWithId),
    {NewStates, Results} = lists:unzip(Res),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(Module, Results, NewStates, sets:new()),
    ConvergedResultsList = sets:to_list(ConvergedResults),
    ct:pal("ConvergedResultsList: ~p~n", [ConvergedResultsList]),
    %% everyone but two should converge
    ?assertEqual(N - 2, sets:size(ConvergedResults)),
    %% everyone should have the same value
    DistinctResults = lists:usort([ Sig || {result, {_J, Sig}} <- sets:to_list(ConvergedResults) ]),
    ?assertEqual(1, length(DistinctResults)),
    ok.

too_many_dead_test(Config) ->
    N = proplists:get_value(n, Config),
    F = 4,
    Module = proplists:get_value(module, Config),
    PubKey = proplists:get_value(pubkey, Config),
    PrivateKeys = proplists:get_value(privatekeys, Config),
    Sid = tpke_pubkey:hash_message(PubKey, crypto:strong_rand_bytes(32)),
    [S0, S1, _S2, S3, _S4] = [hbbft_cc:init(Sk, Sid, N, F) || Sk <- PrivateKeys],
    StatesWithId = lists:zip(lists:seq(0, N - 3), [S0, S1, S3]),
    %% all valid members should call get_coin
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = hbbft_cc:get_coin(State),
                            {{J, NewState}, {J, Result}}
                    end, StatesWithId),
    {NewStates, Results} = lists:unzip(Res),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(Module, Results, NewStates, sets:new()),
    ConvergedResultsList = sets:to_list(ConvergedResults),
    ct:pal("ConvergedResultsList: ~p~n", [ConvergedResultsList]),
    %% nobody should converge
    ?assertEqual(0, sets:size(ConvergedResults)),
    ok.

key_mismatch_f1_test(Config) ->
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config),
    Module = proplists:get_value(module, Config),
    PubKey = proplists:get_value(pubkey, Config),
    Dealer = proplists:get_value(dealer, Config),
    PrivateKeys = proplists:get_value(privatekeys, Config),
    {ok, _, PrivateKeys2} = dealer:deal(Dealer),
    Sid = tpke_pubkey:hash_message(PubKey, crypto:strong_rand_bytes(32)),
    [S0, S1, S2, S3, S4] = [hbbft_cc:init(Sk, Sid, N, F) || Sk <- lists:sublist(PrivateKeys, 3) ++ lists:sublist(PrivateKeys2, 2)],
    StatesWithId = lists:zip(lists:seq(0, N - 1), [S0, S1, S2, S3, S4]),
    %% all valid members should call get_coin
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = hbbft_cc:get_coin(State),
                            {{J, NewState}, {J, Result}}
                    end, StatesWithId),
    {NewStates, Results} = lists:unzip(Res),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(Module, Results, NewStates, sets:new()),
    ConvergedResultsList = sets:to_list(ConvergedResults),
    ct:pal("ConvergedResultsList: ~p~n", [ConvergedResultsList]),
    %% all 5 should converge, but there should be 2 distinct results
    ?assertEqual(5, sets:size(ConvergedResults)),
    DistinctResults = lists:usort([ Sig || {result, {_J, Sig}} <- sets:to_list(ConvergedResults) ]),
    ?assertEqual(2, length(DistinctResults)),
    ok.

key_mismatch_f2_test(Config) ->
    N = proplists:get_value(n, Config),
    F = 2,
    Module = proplists:get_value(module, Config),
    PubKey = proplists:get_value(pubkey, Config),
    Dealer = proplists:get_value(dealer, Config),
    PrivateKeys = proplists:get_value(privatekeys, Config),
    {ok, _, PrivateKeys2} = dealer:deal(Dealer),
    Sid = tpke_pubkey:hash_message(PubKey, crypto:strong_rand_bytes(32)),
    [S0, S1, S2, S3, S4] = [hbbft_cc:init(Sk, Sid, N, F) || Sk <- lists:sublist(PrivateKeys, 3) ++ lists:sublist(PrivateKeys2, 2)],
    StatesWithId = lists:zip(lists:seq(0, N - 1), [S0, S1, S2, S3, S4]),
    %% all valid members should call get_coin
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = hbbft_cc:get_coin(State),
                            {{J, NewState}, {J, Result}}
                    end, StatesWithId),
    {NewStates, Results} = lists:unzip(Res),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(Module, Results, NewStates, sets:new()),
    ConvergedResultsList = sets:to_list(ConvergedResults),
    ct:pal("ConvergedResultsList: ~p~n", [ConvergedResultsList]),
    %% the 3 with the right keys should converge to the same value
    ?assertEqual(3, sets:size(ConvergedResults)),
    DistinctResults = lists:usort([ Sig || {result, {_J, Sig}} <- sets:to_list(ConvergedResults) ]),
    ?assertEqual(1, length(DistinctResults)),
    ok.

mixed_keys_test(Config) ->
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config),
    Module = proplists:get_value(module, Config),
    PubKey = proplists:get_value(pubkey, Config),
    Dealer = proplists:get_value(dealer, Config),
    PrivateKeys = proplists:get_value(privatekeys, Config),
    {ok, _, PrivateKeys2} = dealer:deal(Dealer),

    Sid = tpke_pubkey:hash_message(PubKey, crypto:strong_rand_bytes(32)),

    [S0, S1, S2, _, _] = [hbbft_cc:init(Sk, Sid, N, F) || Sk <- PrivateKeys],
    [_, _, _, S3, S4] = [hbbft_cc:init(Sk, Sid, N, F) || Sk <- PrivateKeys2],

    StatesWithId = lists:zip(lists:seq(0, N - 1), [S0, S1, S2, S3, S4]),
    %% all valid members should call get_coin
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = hbbft_cc:get_coin(State),
                            {{J, NewState}, {J, Result}}
                    end, StatesWithId),
    {NewStates, Results} = lists:unzip(Res),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(Module, Results, NewStates, sets:new()),
    ConvergedResultsList = sets:to_list(ConvergedResults),
    ct:pal("ConvergedResultsList: ~p~n", [ConvergedResultsList]),

    DistinctCoins = sets:from_list([Coin || {result, {_, Coin}} <- sets:to_list(ConvergedResults)]),
    %% two distinct sets have converged with different coins each
    ?assertEqual(2, sets:size(DistinctCoins)),

    %% everyone but two should converge
    ?assertEqual(N, sets:size(ConvergedResults)),
    ok.
