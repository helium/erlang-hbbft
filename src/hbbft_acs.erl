-module(hbbft_acs).

-export([init/4, input/2, handle_msg/3]).

-record(data, {
          secret_key,
          done = false :: boolean(),
          n :: pos_integer(),
          f :: pos_integer(),
          j :: non_neg_integer(),
          rbc = #{} :: #{non_neg_integer() => term()},
          bba = #{} :: #{non_neg_integer() => term()},
          bba_results = #{} :: #{non_neg_integer() => boolean()},
          rbc_results = #{} :: #{non_neg_integer() => binary()}
         }).

init(SK, N, F, J) ->
    %% instanciate all the RBCs
    RBCs = [{I, hbbft_rbc:init(N, F)} || I <- lists:seq(0, N-1)],
    BBAs = [{I, hbbft_bba:init(SK, N, F)} || I <- lists:seq(0, N-1)],
    #data{secret_key=SK, n=N, f=F, j=J, rbc=maps:from_list(RBCs), bba=maps:from_list(BBAs)}.

input(Data, Input) ->
    %% input the message to our RBC
    MyRBC0 = maps:get(Data#data.j, Data#data.rbc),
    {MyRBC, {send, Responses}} = hbbft_rbc:input(MyRBC0, Input),
    {Data#data{rbc=maps:put(Data#data.j, MyRBC, Data#data.rbc)}, {send, hbbft_utils:wrap({rbc, Data#data.j}, Responses)}}.

handle_msg(Data, J, {{rbc, I}, RBCMsg}) ->
    RBC = maps:get(I, Data#data.rbc),
    io:format("~p RBC message for ~p ~p~n", [Data#data.j, I, element(1, RBCMsg)]),
    case hbbft_rbc:handle_msg(RBC, J, RBCMsg) of
        {NewRBC, {send, ToSend}} ->
            {Data#data{rbc=maps:put(I, NewRBC, Data#data.rbc)}, {send, hbbft_utils:wrap({rbc, I}, ToSend)}};
        {NewRBC, {result, Result}} ->
            io:format("~p RBC returned for ~p~n", [Data#data.j, I]),
            %% ok, start the BBA for this RBC
            {BBA, {send, ToSend}} = hbbft_bba:input(maps:get(I, Data#data.bba), 1),
            {Data#data{rbc=maps:put(I, NewRBC, Data#data.rbc),
                       bba=maps:put(I, BBA, Data#data.bba),
                       rbc_results=maps:put(I, Result, Data#data.rbc_results)},
             {send, hbbft_utils:wrap({bba, I}, ToSend)}};
        {NewRBC, ok} ->
            {Data#data{rbc=maps:put(I, NewRBC, Data#data.rbc)}, ok}
    end;
handle_msg(Data = #data{n=N, f=F, secret_key=SK}, J, {{bba, I}, BBAMsg}) ->
    BBA = maps:get(I, Data#data.bba),
    case hbbft_bba:handle_msg(BBA, J, BBAMsg) of
        {NewBBA, {send, ToSend}} ->
            {Data#data{bba=maps:put(I, NewBBA, Data#data.bba)}, {send, hbbft_utils:wrap({bba, I}, ToSend)}};
        {NewBBA, {result, B}} ->
            io:format("~p BBA ~p returned ~p~n", [Data#data.j, I, B]),
            NewBBAResults = maps:put(I, B == 1, Data#data.bba_results),
            %% upon delivery of value 1 from at least N − f instances of BA , provide input 0 to each instance of BA that has not yet been provided input.
            BBAsThatReturnedOne = length([ true || {_, true} <- maps:to_list(NewBBAResults)]),
            case BBAsThatReturnedOne >= N - F andalso Data#data.done == false of
                true ->
                    io:format("~b Enough BBAs (~b/~b) completed, zeroing the rest~n", [Data#data.j, BBAsThatReturnedOne, N]),
                    %% send 0 to all BBAs that have not yet been provided input because their RBC has not completed
                    NewBBAsAndReplies = lists:foldl(fun(E, Acc) ->
                                                            case maps:is_key(E, NewBBAResults) of
                                                                false ->
                                                                    {FailedBBA, {send, ToSend}} = hbbft_bba:input(hbbft_bba:init(SK, N, F), 0),
                                                                    io:format("~p Sending BBA ~p zero~n", [Data#data.j, E]),
                                                                    [{{E, FailedBBA}, hbbft_utils:wrap({bba, E}, ToSend)}|Acc];
                                                                true ->
                                                                    Acc
                                                            end
                                                    end, [], lists:seq(0, N - 1)),
                    {NewBBAs, Replies} = lists:unzip(NewBBAsAndReplies),
                    {Data#data{bba=maps:merge(Data#data.bba, maps:from_list(NewBBAs)), bba_results=NewBBAResults, done=true}, {send, lists:flatten(Replies)}};
                false ->
                    %% check if all the BBA protocols have completed and all the RBC protocols have finished
                    Response = case sets:size(sets:from_list([maps:size(NewBBAResults), maps:size(Data#data.bba),
                                                              maps:size(Data#data.rbc)])) == 1 of
                                   true ->
                                       io:format("All BBAs have completed~n"),
                                       %% construct a 2-tuple list of which BBAs have returned 1 and the corresponding RBC value
                                       ResultVector = [ {E, maps:get(E, Data#data.rbc_results)} || {E, X} <- lists:keysort(1, maps:to_list(NewBBAResults)), X == true],
                                       %% return all the RBC values for which BBA has succeeded
                                       {result, ResultVector};
                                   false ->
                                       ok
                               end,
                    {Data#data{bba=maps:put(I, NewBBA, Data#data.bba), bba_results=NewBBAResults}, Response}
            end;
        {NewBBA, ok} ->
            {Data#data{bba=maps:put(I, NewBBA, Data#data.bba)}, ok}
    end.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

init_test_() ->
    {timeout, 60, [
                   fun() ->
                           N = 5,
                           F = N div 4,
                           dealer:start_link(N, F+1, 'SS512'),
                           {ok, _PubKey, PrivateKeys} = dealer:deal(),
                           gen_server:stop(dealer),
                           Msgs = [ crypto:strong_rand_bytes(512) || _ <- lists:seq(1, N)],
                           StatesWithId = [{J, hbbft_acs:init(Sk, N, F, J)} || {J, Sk} <- lists:zip(lists:seq(0, N - 1), PrivateKeys)],
                           MixedList = lists:zip(Msgs, StatesWithId),
                           Res = lists:map(fun({Msg, {J, State}}) ->
                                                   {NewState, Result} = input(State, Msg),
                                                   {{J, NewState}, {J, Result}}
                                           end, MixedList),
                           {NewStates, Results} = lists:unzip(Res),
                           {_, ConvergedResults} = do_send_outer(Results, NewStates, sets:new()),
                           ?assertEqual(N, sets:size(ConvergedResults)),
                           DistinctResults = sets:from_list([BVal || {result, {_, BVal}} <- sets:to_list(ConvergedResults)]),
                           ?assertEqual(1, sets:size(DistinctResults)),
                           ?assert(sets:is_subset(sets:from_list([ X || {_, X} <- lists:flatten(sets:to_list(DistinctResults))]), sets:from_list(Msgs))),
                           ok
                   end]}.

do_send_outer([], States, Acc) ->
    {States, Acc};
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
