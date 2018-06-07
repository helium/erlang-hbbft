-module(hbbft_bba_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, init_per_testcase/2, end_per_testcase/2]).
-export([termination_test/1,
         init_test/1,
         init_with_zeroes_test/1,
         init_with_ones_test/1,
         init_with_mixed_zeros_and_ones_test/1,
         one_dead_test/1,
         two_dead_test/1
        ]).

all() ->
    [termination_test,
     init_test,
     init_with_zeroes_test,
     init_with_ones_test,
     init_with_mixed_zeros_and_ones_test,
     one_dead_test,
     two_dead_test
    ].

init_per_testcase(_, Config) ->
    N = 5,
    F = N div 4,
    Module = hbbft_bba,
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

termination_test(Config) ->
    Module = proplists:get_value(module, Config),
    Fun = fun(Vals) ->
                  N = 7,
                  F = 2,
                  {ok, Dealer} = dealer:start_link(N, F+1, 'SS512'),
                  {ok, _PubKey, PrivateKeys} = dealer:deal(Dealer),
                  gen_server:stop(Dealer),
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
    {ok, Dealer} = dealer:start_link(N, F+1, 'SS512'),
    {ok, _PubKey, PrivateKeys} = dealer:deal(Dealer),
    gen_server:stop(Dealer),
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
    ZeroList = lists:zip([1, 0, 0, 0, 0], StatesWithId),
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
    OneList = lists:zip([1, 1, 1, 1, 0], StatesWithId),
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
    {ok, Dealer} = dealer:start_link(N, F+1, 'SS512'),
    {ok, _PubKey, PrivateKeys} = dealer:deal(Dealer),
    gen_server:stop(Dealer),
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

one_dead_test(Config) ->
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config),
    Module = proplists:get_value(module, Config),
    PrivateKeys = proplists:get_value(privatekeys, Config),
    [S0, S1, _S2, S3, S4] = [hbbft_bba:init(Sk, N, F) || Sk <- PrivateKeys],
    StatesWithId = lists:zip(lists:seq(0, N - 2), [S0, S1, S3, S4]),
    %% all valid members should call get_coin
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = hbbft_bba:input(State, 1),
                            {{J, NewState}, {J, Result}}
                    end, StatesWithId),
    {NewStates, Results} = lists:unzip(Res),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(Module, Results, NewStates, sets:new()),
    ConvergedResultsList = sets:to_list(ConvergedResults),
    ct:pal("ConvergedResultsList: ~p~n", [ConvergedResultsList]),
    %% everyone but one should converge
    ?assertEqual(N - 1, sets:size(ConvergedResults)),
    ok.

two_dead_test(Config) ->
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config),
    Module = proplists:get_value(module, Config),
    PrivateKeys = proplists:get_value(privatekeys, Config),
    [S0, S1, _S2, S3, _S4] = [hbbft_bba:init(Sk, N, F) || Sk <- PrivateKeys],
    StatesWithId = lists:zip(lists:seq(0, N - 3), [S0, S1, S3]),
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
