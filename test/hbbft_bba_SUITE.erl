-module(hbbft_bba_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, init_per_testcase/2, end_per_testcase/2]).
-export([termination_test/1,
         init_test/1,
         init_with_zeroes_test/1,
         init_with_ones_test/1,
         init_with_mixed_zeros_and_ones_test/1,
         f_dead_test/1,
         fplusone_dead_test/1
        ]).

all() ->
    [termination_test,
     init_test,
     init_with_zeroes_test,
     init_with_ones_test,
     init_with_mixed_zeros_and_ones_test,
     f_dead_test,
     fplusone_dead_test
    ].

init_per_testcase(_, Config) ->
    N = list_to_integer(os:getenv("N", "34")),
    F = (N - 1) div 3,
    Module = hbbft_bba,
    {ok, Dealer} = dealer:new(N, F+1, 'SS512'),
    {ok, {PubKey, PrivateKeys}} = dealer:deal(Dealer),
    [{n, N}, {f, F}, {dealer, Dealer}, {module, Module}, {pubkey, PubKey}, {privatekeys, PrivateKeys} | Config].

end_per_testcase(_, _Config) ->
    ok.

termination_test(Config) ->
    Module = proplists:get_value(module, Config),
    Fun = fun(Vals) ->
                  N = 7,
                  F = 2,
                  {ok, Dealer} = dealer:new(N, F+1, 'SS512'),
                  {ok, {_PubKey, PrivateKeys}} = dealer:deal(Dealer),
                  States = [hbbft_bba:init(Sk, N, F) || Sk <- PrivateKeys],
                  StatesWithId = lists:zip(lists:seq(0, length(States) - 1), States),
                  MixedList = lists:zip(Vals, StatesWithId),
                  %% all valid members should call get_coin
                  Res = lists:map(fun({I, {J, State}}) ->
                                          {NewState, Result} = hbbft_bba:input(State, I),
                                          {{J, NewState}, {J, Result}}
                                  end, MixedList),
                  {NewStates, Results} = lists:unzip(Res),
                  {_FinalStates, ConvergedResults} = hbbft_test_utils:do_send_outer(Module, Results, NewStates, sets:new()),
                  ConvergedResultsList = sets:to_list(ConvergedResults),
                  ct:pal("ConvergedResultsList: ~p~n", [ConvergedResultsList]),
                  DistinctResults = sets:from_list([BVal || {result, {_, BVal}} <- sets:to_list(ConvergedResults)]),
                  ?assertEqual(N, sets:size(ConvergedResults)),
                  ?assertEqual(1, sets:size(DistinctResults)),
                  ok
          end,
    Values = [[1, 0, 0, 0, 0, 0, 0],
              [1, 1, 0, 0, 0, 0, 0],
              [1, 1, 1, 0, 0, 0, 0],
              [1, 1, 1, 1, 0, 0, 0],
              [1, 1, 1, 1, 1, 0, 0],
              [1, 1, 1, 1, 1, 1, 0],
              [1, 1, 1, 1, 1, 1, 1]],
    [Fun(Val) || Val <- Values].

init_test(Config) ->
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config),
    Module = proplists:get_value(module, Config),
    {ok, Dealer} = dealer:new(N, F+1, 'SS512'),
    {ok, {_PubKey, PrivateKeys}} = dealer:deal(Dealer),
    States = [hbbft_bba:init(Sk, N, F) || Sk <- PrivateKeys],
    StatesWithId = lists:zip(lists:seq(0, length(States) - 1), States),
    %% all valid members should call get_coin
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = hbbft_bba:input(State, 1),
                            {{J, NewState}, {J, Result}}
                    end, StatesWithId),
    {NewStates, Results} = lists:unzip(Res),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(Module, Results, NewStates, sets:new()),
    ConvergedResultsList = sets:to_list(ConvergedResults),
    ct:pal("ConvergedResultsList: ~p~n", [ConvergedResultsList]),
    %% everyone should converge
    ?assertEqual(N, sets:size(ConvergedResults)),
    ok.

init_with_zeroes_test(Config) ->
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config),
    Module = proplists:get_value(module, Config),
    PrivateKeys = proplists:get_value(privatekeys, Config),
    States = [hbbft_bba:init(Sk, N, F) || Sk <- PrivateKeys],
    StatesWithId = lists:zip(lists:seq(0, length(States) - 1), States),
    ZeroList = lists:zip([1|lists:duplicate(N-1, 0)], StatesWithId),
    %% all valid members should call get_coin
    Res = lists:map(fun({I, {J, State}}) ->
                            {NewState, Result} = hbbft_bba:input(State, I),
                            {{J, NewState}, {J, Result}}
                    end, ZeroList),
    {NewStates, Results} = lists:unzip(Res),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(Module, Results, NewStates, sets:new()),
    ConvergedResultsList = sets:to_list(ConvergedResults),
    ct:pal("ConvergedResultsList: ~p~n", [ConvergedResultsList]),
    DistinctResults = sets:from_list([BVal || {result, {_, BVal}} <- sets:to_list(ConvergedResults)]),
    ?assertEqual(N, sets:size(ConvergedResults)),
    ?assertEqual([0], sets:to_list(DistinctResults)),
    ok.

init_with_ones_test(Config) ->
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config),
    Module = proplists:get_value(module, Config),
    PrivateKeys = proplists:get_value(privatekeys, Config),
    States = [hbbft_bba:init(Sk, N, F) || Sk <- PrivateKeys],
    StatesWithId = lists:zip(lists:seq(0, length(States) - 1), States),
    OneList = lists:zip(lists:duplicate(N-1, 1) ++ [0], StatesWithId),
    %% all valid members should call get_coin
    Res = lists:map(fun({I, {J, State}}) ->
                            {NewState, Result} = hbbft_bba:input(State, I),
                            {{J, NewState}, {J, Result}}
                    end, OneList),
    {NewStates, Results} = lists:unzip(Res),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(Module, Results, NewStates, sets:new()),
    ConvergedResultsList = sets:to_list(ConvergedResults),
    ct:pal("ConvergedResultsList: ~p~n", [ConvergedResultsList]),
    DistinctResults = sets:from_list([BVal || {result, {_, BVal}} <- sets:to_list(ConvergedResults)]),
    ?assertEqual(N, sets:size(ConvergedResults)),
    ?assertEqual([1], sets:to_list(DistinctResults)),
    ok.

init_with_mixed_zeros_and_ones_test(Config) ->
    Module = proplists:get_value(module, Config),
    N = 10,
    F = 2,
    {ok, Dealer} = dealer:new(N, F+1, 'SS512'),
    {ok, {_PubKey, PrivateKeys}} = dealer:deal(Dealer),
    States = [hbbft_bba:init(Sk, N, F) || Sk <- PrivateKeys],
    StatesWithId = lists:zip(lists:seq(0, length(States) - 1), States),
    MixedList = lists:zip([1, 1, 1, 0, 1, 0, 0, 0, 0, 0], StatesWithId),
    %% all valid members should call get_coin
    Res = lists:map(fun({I, {J, State}}) ->
                            {NewState, Result} = hbbft_bba:input(State, I),
                            {{J, NewState}, {J, Result}}
                    end, MixedList),
    {NewStates, Results} = lists:unzip(Res),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(Module, Results, NewStates, sets:new()),
    ConvergedResultsList = sets:to_list(ConvergedResults),
    ct:pal("ConvergedResultsList: ~p~n", [ConvergedResultsList]),
    DistinctResults = sets:from_list([BVal || {result, {_, BVal}} <- sets:to_list(ConvergedResults)]),
    ?assertEqual(N, sets:size(ConvergedResults)),
    ?assertEqual(1, sets:size(DistinctResults)),
    ok.

f_dead_test(Config) ->
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config),
    Module = proplists:get_value(module, Config),
    PrivateKeys = proplists:get_value(privatekeys, Config),
    States = lists:sublist([hbbft_bba:init(Sk, N, F) || Sk <- PrivateKeys], 1, N-F),
    StatesWithId = lists:zip(lists:seq(0, N - 1 - F), States),
    %% all valid members should call get_coin
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = hbbft_bba:input(State, 1),
                            {{J, NewState}, {J, Result}}
                    end, StatesWithId),
    {NewStates, Results} = lists:unzip(Res),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(Module, Results, NewStates, sets:new()),
    ConvergedResultsList = sets:to_list(ConvergedResults),
    ct:pal("ConvergedResultsList: ~p~n", [ConvergedResultsList]),
    %% everyone but F should converge
    ?assertEqual(N - F, sets:size(ConvergedResults)),
    ok.

fplusone_dead_test(Config) ->
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config),
    Module = proplists:get_value(module, Config),
    PrivateKeys = proplists:get_value(privatekeys, Config),
    States = lists:sublist([hbbft_bba:init(Sk, N, F) || Sk <- PrivateKeys], 1, N - (F + 1)),
    StatesWithId = lists:zip(lists:seq(0, N - 1 - (F + 1)), States),
    %% all valid members should call get_coin
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = hbbft_bba:input(State, 1),
                            {{J, NewState}, {J, Result}}
                    end, StatesWithId),
    {NewStates, Results} = lists:unzip(Res),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(Module, Results, NewStates, sets:new()),
    ConvergedResultsList = sets:to_list(ConvergedResults),
    ct:pal("ConvergedResultsList: ~p~n", [ConvergedResultsList]),
    %% should not converge
    ?assertEqual(0, sets:size(ConvergedResults)),
    ok.
