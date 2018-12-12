-module(hbbft_acs_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-include_lib("relcast/include/fakecast.hrl").

-export([all/0, init_per_testcase/2, end_per_testcase/2]).
-export([
         init_test/1,
         one_dead_test/1,
         f_dead_test/1,
         fplusone_dead_test/1,
         fakecast_test/1
        ]).

all() ->
    [
     init_test,
     one_dead_test,
     f_dead_test,
     fplusone_dead_test,
     fakecast_test
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

one_dead_test(Config) ->
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

f_dead_test(Config) ->
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
                    end, lists:sublist(MixedList, N-F)),
    {NewStates, Results} = lists:unzip(Res),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(Module, Results, NewStates, sets:new()),
    ConvergedResultsList = sets:to_list(ConvergedResults),
    ct:pal("ConvergedResultsList: ~p~n", [ConvergedResultsList]),
    ?assertEqual(N - F, sets:size(ConvergedResults)),
    DistinctResults = sets:from_list([BVal || {result, {_, BVal}} <- sets:to_list(ConvergedResults)]),
    ?assertEqual(1, sets:size(DistinctResults)),
    ?assert(sets:is_subset(sets:from_list([ X || {_, X} <- lists:flatten(sets:to_list(DistinctResults))]), sets:from_list(Msgs))),
    ok.

fplusone_dead_test(Config) ->
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
                    end, lists:sublist(MixedList, N-(F+1))),
    {NewStates, Results} = lists:unzip(Res),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(Module, Results, NewStates, sets:new()),
    ConvergedResultsList = sets:to_list(ConvergedResults),
    ct:pal("ConvergedResultsList: ~p~n", [ConvergedResultsList]),
    ?assertEqual(0, sets:size(ConvergedResults)),
    ok.

-record(state,
        {
         node_count :: integer(),
         stopped = false :: boolean(),
         results = sets:new() :: sets:set()
        }).

trivial(_Message, _From, To, _NodeState, _NewState, {result, Result},
        #state{results = Results0} = State) ->
    Results = sets:add_element({result, {To, Result}}, Results0),
    %% ct:pal("results len ~p ~p", [sets:size(Results), sets:to_list(Results)]),
    case sets:size(Results) == State#state.node_count of
        true ->
            {result, Results};
        false ->
            {actions, [], State#state{results = Results}}
    end;
trivial(_Message, _From, To, _NodeState, _NewState, {result_and_send, Result, _Msgs},
        #state{results = Results0} = State) ->
    Results = sets:add_element({result, {To, Result}}, Results0),
    %% ct:pal("results len ~p ~p", [sets:size(Results), sets:to_list(Results)]),
    case sets:size(Results) == State#state.node_count of
        true ->
            {result, Results};
        false ->
            {actions, [], State#state{results = Results}}
    end;
trivial(_Message, _From, _To, _NodeState, _NewState, _Actions, ModelState) ->
    {actions, [], ModelState}.

fakecast_test(Config) ->
    N = 4, % proplists:get_value(n, Config),
    F = 1, % proplists:get_value(f, Config),
    Module = proplists:get_value(module, Config),
    PrivateKeys0 = proplists:get_value(privatekeys, Config),

    {PrivateKeys, _} = lists:split(N, PrivateKeys0),

    Init = fun() ->
                   {ok,
                    #fc_conf{
                       test_mod = Module,
                       nodes = lists:seq(1, N),  %% are names useful?
                       configs = [[Sk, N, F, ID]
                                  || {ID, Sk} <- lists:zip(lists:seq(0, N - 1), PrivateKeys)]
                    },
                    #state{node_count = N - F}
                   }
           end,


    Msgs = [ crypto:strong_rand_bytes(512) || _ <- lists:seq(1, N)],
    Input =
        fun() ->
                lists:zip(lists:seq(0, N - 1), Msgs)
        end,
    Seed = os:timestamp(),
    %% try
        {ok, ConvergedResults} = fakecast:start_test(Init, fun trivial/7,
                                                     Seed,
                                                     Input),
        ConvergedResultsList = sets:to_list(ConvergedResults),
        ct:pal("ConvergedResultsList: ~p~n", [ConvergedResultsList]),
        ?assertEqual(N - F, sets:size(ConvergedResults)),
        DistinctResults = sets:from_list([BVal || {result, {_, BVal}} <- sets:to_list(ConvergedResults)]),
        ?assertEqual(1, sets:size(DistinctResults)),
        ?assert(sets:is_subset(
                  sets:from_list([ X || {_, X} <- lists:flatten(sets:to_list(DistinctResults))]),
                  sets:from_list(Msgs))),
        ok.
    %% catch _:E ->
    %%         throw({fail, Seed, E})
    %% end.
