-module(hbbft_acs_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, init_per_testcase/2, end_per_testcase/2]).
-export([
         init_test/1,
         one_dead/1
        ]).

all() ->
    [
     init_test,
     one_dead
    ].

init_per_testcase(_, Config) ->
    N = list_to_integer(os:getenv("N", "34")),
    F = N div 4,
    Module = hbbft_acs,
    {ok, Dealer} = dealer:new(N, F+1, 'SS512'),
    {ok, {_PubKey, PrivateKeys}} = dealer:deal(Dealer),
    [{n, N}, {f, F}, {module, Module}, {privatekeys, PrivateKeys} | Config].

end_per_testcase(_, _Config) ->
    ok.

init_test(Config) ->
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config),
    Module = proplists:get_value(module, Config),
    PrivateKeys = proplists:get_value(privatekeys, Config),
    Msgs = [ crypto:strong_rand_bytes(512) || _ <- lists:seq(1, N)],
    StatesWithId = [{J, hbbft_acs:init(Sk, N, F, J)} || {J, Sk} <- lists:zip(lists:seq(0, N - 1), PrivateKeys)],
    MixedList = lists:zip(Msgs, StatesWithId),
    Res = lists:map(fun({Msg, {J, State}}) ->
                            {NewState, Result} = hbbft_acs:input(State, Msg),
                            {{J, NewState}, {J, Result}}
                    end, MixedList),
    {NewStates, Results} = lists:unzip(Res),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(Module, Results, NewStates, sets:new()),
    ConvergedResultsList = sets:to_list(ConvergedResults),
    ct:pal("ConvergedResultsList: ~p~n", [ConvergedResultsList]),
    ?assertEqual(N, sets:size(ConvergedResults)),
    DistinctResults = sets:from_list([BVal || {result, {_, BVal}} <- sets:to_list(ConvergedResults)]),
    ?assertEqual(1, sets:size(DistinctResults)),
    ?assert(sets:is_subset(sets:from_list([ X || {_, X} <- lists:flatten(sets:to_list(DistinctResults))]), sets:from_list(Msgs))),
    ok.

one_dead(Config) ->
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config),
    Module = proplists:get_value(module, Config),
    PrivateKeys = proplists:get_value(privatekeys, Config),
    Msgs = [ crypto:strong_rand_bytes(512) || _ <- lists:seq(1, N)],
    StatesWithId = [{J, hbbft_acs:init(Sk, N, F, J)} || {J, Sk} <- lists:zip(lists:seq(0, N - 1), PrivateKeys)],
    MixedList = lists:zip(Msgs, StatesWithId),
    Res = lists:map(fun({Msg, {J, State}}) ->
                            {NewState, Result} = hbbft_acs:input(State, Msg),
                            {{J, NewState}, {J, Result}}
                    end, tl(MixedList)),
    {NewStates, Results} = lists:unzip(Res),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(Module, Results, NewStates, sets:new()),
    ConvergedResultsList = sets:to_list(ConvergedResults),
    ct:pal("ConvergedResultsList: ~p~n", [ConvergedResultsList]),
    ?assertEqual(N - 1, sets:size(ConvergedResults)),
    DistinctResults = sets:from_list([BVal || {result, {_, BVal}} <- sets:to_list(ConvergedResults)]),
    ?assertEqual(1, sets:size(DistinctResults)),
    ?assert(sets:is_subset(sets:from_list([ X || {_, X} <- lists:flatten(sets:to_list(DistinctResults))]), sets:from_list(Msgs))),
    ok.
