-module(hbbft_cc_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, init_per_testcase/2, end_per_testcase/2]).
-export([
         init_test/1,
         f_dead_test/1,
         fplusone_dead_test/1,
         too_many_dead_test/1,
         key_mismatch_f9_test/1,
         key_mismatch_f10_test/1,
         mixed_keys_test/1
        ]).

all() ->
    [
     init_test,
     f_dead_test,
     fplusone_dead_test,
     too_many_dead_test,
     key_mismatch_f9_test,
     key_mismatch_f10_test,
     mixed_keys_test
    ].

init_per_testcase(_, Config) ->
    N = list_to_integer(os:getenv("N", "34")),
    F = N div 4,
    Module = hbbft_cc,
    {ok, Dealer} = dealer:new(N, F+1, 'SS512'),
    {ok, {PubKey, PrivateKeys}} = dealer:deal(Dealer),
    [{n, N}, {f, F}, {dealer, Dealer}, {module, Module}, {pubkey, PubKey}, {privatekeys, PrivateKeys} | Config].

end_per_testcase(_, _Config) ->
    ok.

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

f_dead_test(Config) ->
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config),
    Module = proplists:get_value(module, Config),
    PubKey = proplists:get_value(pubkey, Config),
    PrivateKeys = proplists:get_value(privatekeys, Config),
    Sid = tpke_pubkey:hash_message(PubKey, crypto:strong_rand_bytes(32)),
    InitialStates = [hbbft_cc:init(Sk, Sid, N, F) || Sk <- PrivateKeys],
    ToCrash = hbbft_test_utils:random_n(F, InitialStates),
    StatesAfterCrash = ordsets:to_list(ordsets:subtract(ordsets:from_list(InitialStates),ordsets:from_list(ToCrash))),
    StatesWithId = lists:zip(lists:seq(0, N-F-1), StatesAfterCrash),
    ct:pal("StatesWithId: ~p, len: ~p", [StatesWithId, length(StatesWithId)]),
    %% all valid members should call get_coin
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = hbbft_cc:get_coin(State),
                            {{J, NewState}, {J, Result}}
                    end, StatesWithId),
    {NewStates, Results} = lists:unzip(Res),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(Module, Results, NewStates, sets:new()),
    ConvergedResultsList = sets:to_list(ConvergedResults),
    ct:pal("ConvergedResultsList: ~p~n", [ConvergedResultsList]),
    %% everyone except F should converge
    ?assertEqual(N - F, sets:size(ConvergedResults)),
    %% everyone should have the same value
    DistinctResults = lists:usort([ Sig || {result, {_J, Sig}} <- sets:to_list(ConvergedResults) ]),
    ?assertEqual(1, length(DistinctResults)),
    ok.

fplusone_dead_test(Config) ->
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config) + 1,
    Module = proplists:get_value(module, Config),
    PubKey = proplists:get_value(pubkey, Config),
    PrivateKeys = proplists:get_value(privatekeys, Config),
    Sid = tpke_pubkey:hash_message(PubKey, crypto:strong_rand_bytes(32)),
    InitialStates = [hbbft_cc:init(Sk, Sid, N, F) || Sk <- PrivateKeys],
    ToCrash = hbbft_test_utils:random_n(F+1, InitialStates),
    StatesAfterCrash = ordsets:to_list(ordsets:subtract(ordsets:from_list(InitialStates),ordsets:from_list(ToCrash))),
    StatesWithId = lists:zip(lists:seq(0, N-(F+1)-1), StatesAfterCrash),
    %% all valid members should call get_coin
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = hbbft_cc:get_coin(State),
                            {{J, NewState}, {J, Result}}
                    end, StatesWithId),
    {NewStates, Results} = lists:unzip(Res),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(Module, Results, NewStates, sets:new()),
    ConvergedResultsList = sets:to_list(ConvergedResults),
    ct:pal("ConvergedResultsList: ~p~n", [ConvergedResultsList]),
    %% everyone except F + 1 should converge
    ?assertEqual(N - (F+1), sets:size(ConvergedResults)),
    %% everyone should have the same value
    DistinctResults = lists:usort([ Sig || {result, {_J, Sig}} <- sets:to_list(ConvergedResults) ]),
    ?assertEqual(1, length(DistinctResults)),
    ok.

too_many_dead_test(Config) ->
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config) + (N div 2),
    Module = proplists:get_value(module, Config),
    PubKey = proplists:get_value(pubkey, Config),
    PrivateKeys = proplists:get_value(privatekeys, Config),
    Sid = tpke_pubkey:hash_message(PubKey, crypto:strong_rand_bytes(32)),

    InitialStates = [hbbft_cc:init(Sk, Sid, N, F) || Sk <- PrivateKeys],
    ToCrash = hbbft_test_utils:random_n(F, InitialStates),
    StatesAfterCrash = ordsets:to_list(ordsets:subtract(ordsets:from_list(InitialStates), ordsets:from_list(ToCrash))),
    StatesWithId = lists:zip(lists:seq(0, N-F-1), StatesAfterCrash),

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

key_mismatch_f9_test(Config) ->
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config),
    Module = proplists:get_value(module, Config),
    PubKey = proplists:get_value(pubkey, Config),
    Dealer = proplists:get_value(dealer, Config),
    PrivateKeys = proplists:get_value(privatekeys, Config),
    {ok, {_, PrivateKeys2}} = dealer:deal(Dealer),
    Sid = tpke_pubkey:hash_message(PubKey, crypto:strong_rand_bytes(32)),
    %% choose 20 from pk1
    %% choose 17 from pk2
    InitialStates = [hbbft_cc:init(Sk, Sid, N, F) || Sk <- lists:sublist(PrivateKeys, (N-2*F)) ++ lists:sublist(PrivateKeys2, 2*F)],
    StatesWithId = lists:zip(lists:seq(0, N - 1), InitialStates),
    %% all valid members should call get_coin
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = hbbft_cc:get_coin(State),
                            {{J, NewState}, {J, Result}}
                    end, StatesWithId),
    {NewStates, Results} = lists:unzip(Res),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(Module, Results, NewStates, sets:new()),
    ConvergedResultsList = sets:to_list(ConvergedResults),
    ct:pal("ConvergedResultsList: ~p~n", [ConvergedResultsList]),
    %% all N should converge, but there should be 2 distinct results
    ?assertEqual(N, sets:size(ConvergedResults)),
    DistinctResults = lists:usort([ Sig || {result, {_J, Sig}} <- sets:to_list(ConvergedResults) ]),
    ?assertEqual(2, length(DistinctResults)),
    ok.

key_mismatch_f10_test(Config) ->
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config) + 1,
    Module = proplists:get_value(module, Config),
    PubKey = proplists:get_value(pubkey, Config),
    Dealer = proplists:get_value(dealer, Config),
    PrivateKeys = proplists:get_value(privatekeys, Config),
    {ok, {_, PrivateKeys2}} = dealer:deal(Dealer),
    Sid = tpke_pubkey:hash_message(PubKey, crypto:strong_rand_bytes(32)),
    InitialStates = [hbbft_cc:init(Sk, Sid, N, F) || Sk <- lists:sublist(PrivateKeys, N-F) ++ lists:sublist(PrivateKeys2, F)],
    StatesWithId = lists:zip(lists:seq(0, N - 1), InitialStates),
    %% all valid members should call get_coin
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = hbbft_cc:get_coin(State),
                            {{J, NewState}, {J, Result}}
                    end, StatesWithId),
    {NewStates, Results} = lists:unzip(Res),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(Module, Results, NewStates, sets:new()),
    ConvergedResultsList = sets:to_list(ConvergedResults),
    ct:pal("ConvergedResultsList: ~p~n", [ConvergedResultsList]),
    %% the N-F with the right keys should converge
    %% and there should be one distinct result
    ?assertEqual(N-F, sets:size(ConvergedResults)),
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
    {ok, {_, PrivateKeys2}} = dealer:deal(Dealer),

    Sid = tpke_pubkey:hash_message(PubKey, crypto:strong_rand_bytes(32)),

    InitialState1 = [hbbft_cc:init(Sk, Sid, N, F) || Sk <- PrivateKeys],
    InitialState2 = [hbbft_cc:init(Sk, Sid, N, F) || Sk <- PrivateKeys2],

    InitialStates = hbbft_test_utils:random_n(2*F, InitialState1) ++ hbbft_test_utils:random_n(N-2*F, InitialState2),

    StatesWithId = lists:zip(lists:seq(0, N - 1), InitialStates),
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
