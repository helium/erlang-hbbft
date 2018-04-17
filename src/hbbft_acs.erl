-module(hbbft_acs).

-export([init/4, input/2, handle_msg/3]).

-record(acs_data, {
          secret_key :: tpke_privkey:privkey(),
          done = false :: boolean(),
          n :: pos_integer(),
          f :: non_neg_integer(),
          j :: non_neg_integer(),
          rbc = #{} :: #{non_neg_integer() => hbbft_rbc:rbc_data()},
          bba = #{} :: #{non_neg_integer() => hbbft_bba:bba_data()},
          bba_results = #{} :: #{non_neg_integer() => boolean()},
          rbc_results = #{} :: #{non_neg_integer() => binary()}
         }).

-type acs_data() :: #acs_data{}.

-spec init(tpke_privkey:privkey(), pos_integer(), non_neg_integer(), non_neg_integer()) -> acs_data().
init(SK, N, F, J) ->
    %% instanciate all the RBCs
    RBCs = [{I, hbbft_rbc:init(N, F)} || I <- lists:seq(0, N-1)],
    BBAs = [{I, hbbft_bba:init(SK, N, F)} || I <- lists:seq(0, N-1)],
    #acs_data{secret_key=SK, n=N, f=F, j=J, rbc=maps:from_list(RBCs), bba=maps:from_list(BBAs)}.

-spec input(acs_data(), binary()) -> {acs_data(), {send, [{multicast, {{rbc, non_neg_integer()}, binary()}}]}}.
input(Data, Input) ->
    %% input the message to our RBC
    MyRBC0 = maps:get(Data#acs_data.j, Data#acs_data.rbc),
    {MyRBC, {send, Responses}} = hbbft_rbc:input(MyRBC0, Input),
    {Data#acs_data{rbc=maps:put(Data#acs_data.j, MyRBC, Data#acs_data.rbc)}, {send, hbbft_utils:wrap({rbc, Data#acs_data.j}, Responses)}}.

handle_msg(Data, J, {{rbc, I}, RBCMsg}) ->
    RBC = maps:get(I, Data#acs_data.rbc),
    io:format("~p RBC message for ~p ~p~n", [Data#acs_data.j, I, element(1, RBCMsg)]),
    case hbbft_rbc:handle_msg(RBC, J, RBCMsg) of
        {NewRBC, {send, ToSend}} ->
            {Data#acs_data{rbc=maps:put(I, NewRBC, Data#acs_data.rbc)}, {send, hbbft_utils:wrap({rbc, I}, ToSend)}};
        {NewRBC, {result, Result}} ->
            io:format("~p RBC returned for ~p~n", [Data#acs_data.j, I]),
            %% ok, start the BBA for this RBC
            {BBA, {send, ToSend}} = hbbft_bba:input(maps:get(I, Data#acs_data.bba), 1),
            {Data#acs_data{rbc=maps:put(I, NewRBC, Data#acs_data.rbc),
                       bba=maps:put(I, BBA, Data#acs_data.bba),
                       rbc_results=maps:put(I, Result, Data#acs_data.rbc_results)},
             {send, hbbft_utils:wrap({bba, I}, ToSend)}};
        {NewRBC, ok} ->
            {Data#acs_data{rbc=maps:put(I, NewRBC, Data#acs_data.rbc)}, ok}
    end;
handle_msg(Data = #acs_data{n=N, f=F, secret_key=SK}, J, {{bba, I}, BBAMsg}) ->
    BBA = maps:get(I, Data#acs_data.bba),
    case hbbft_bba:handle_msg(BBA, J, BBAMsg) of
        {NewBBA, {send, ToSend}} ->
            {Data#acs_data{bba=maps:put(I, NewBBA, Data#acs_data.bba)}, {send, hbbft_utils:wrap({bba, I}, ToSend)}};
        {NewBBA, {result, B}} ->
            io:format("~p BBA ~p returned ~p~n", [Data#acs_data.j, I, B]),
            NewBBAResults = maps:put(I, B == 1, Data#acs_data.bba_results),
            %% upon delivery of value 1 from at least N − f instances of BA , provide input 0 to each instance of BA that has not yet been provided input.
            BBAsThatReturnedOne = length([ true || {_, true} <- maps:to_list(NewBBAResults)]),
            case BBAsThatReturnedOne >= N - F andalso Data#acs_data.done == false of
                true ->
                    io:format("~b Enough BBAs (~b/~b) completed, zeroing the rest~n", [Data#acs_data.j, BBAsThatReturnedOne, N]),
                    %% send 0 to all BBAs that have not yet been provided input because their RBC has not completed
                    NewBBAsAndReplies = lists:foldl(fun(E, Acc) ->
                                                            case maps:is_key(E, NewBBAResults) of
                                                                false ->
                                                                    {FailedBBA, {send, ToSend}} = hbbft_bba:input(hbbft_bba:init(SK, N, F), 0),
                                                                    io:format("~p Sending BBA ~p zero~n", [Data#acs_data.j, E]),
                                                                    [{{E, FailedBBA}, hbbft_utils:wrap({bba, E}, ToSend)}|Acc];
                                                                true ->
                                                                    Acc
                                                            end
                                                    end, [], lists:seq(0, N - 1)),
                    {NewBBAs, Replies} = lists:unzip(NewBBAsAndReplies),
                    {Data#acs_data{bba=maps:merge(Data#acs_data.bba, maps:from_list(NewBBAs)), bba_results=NewBBAResults, done=true}, {send, lists:flatten(Replies)}};
                false ->
                    %% check if all the BBA protocols have completed and all the RBC protocols have finished
                    Response = case sets:size(sets:from_list([maps:size(NewBBAResults), maps:size(Data#acs_data.bba),
                                                              maps:size(Data#acs_data.rbc)])) == 1 of
                                   true ->
                                       io:format("All BBAs have completed~n"),
                                       %% construct a 2-tuple list of which BBAs have returned 1 and the corresponding RBC value
                                       ResultVector = [ {E, maps:get(E, Data#acs_data.rbc_results)} || {E, X} <- lists:keysort(1, maps:to_list(NewBBAResults)), X == true],
                                       %% return all the RBC values for which BBA has succeeded
                                       {result, ResultVector};
                                   false ->
                                       ok
                               end,
                    {Data#acs_data{bba=maps:put(I, NewBBA, Data#acs_data.bba), bba_results=NewBBAResults}, Response}
            end;
        {NewBBA, ok} ->
            {Data#acs_data{bba=maps:put(I, NewBBA, Data#acs_data.bba)}, ok}
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
                           {_, ConvergedResults} = hbbft_test_utils:do_send_outer(?MODULE, Results, NewStates, sets:new()),
                           ?assertEqual(N, sets:size(ConvergedResults)),
                           DistinctResults = sets:from_list([BVal || {result, {_, BVal}} <- sets:to_list(ConvergedResults)]),
                           ?assertEqual(1, sets:size(DistinctResults)),
                           ?assert(sets:is_subset(sets:from_list([ X || {_, X} <- lists:flatten(sets:to_list(DistinctResults))]), sets:from_list(Msgs))),
                           ok
                   end]}.
-endif.
