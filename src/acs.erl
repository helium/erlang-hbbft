-module(acs).

-export([init/3, input/3, handle_msg/3]).

-record(data, {
          secret_key,
          done = false :: boolean(),
          n :: pos_integer(),
          f :: pos_integer(),
          rbc = #{} :: #{non_neg_integer() => term()},
          bba = #{} :: #{non_neg_integer() => term()},
          bba_results = #{} :: #{non_neg_integer() => boolean()},
          rbc_results = #{} :: #{non_neg_integer() => binary()}
         }).

init(SK, N, F) ->
    #data{secret_key=SK, n=N, f=F}.

input(Data = #data{n=N, f=F}, J, Input) ->
    %% init the RBCs and input the message to them
    RBCs = [{I, reliable_broadcast:init(N, F, 512)} || I <- lists:seq(0, N-1)],
    {J, MyRBC0} = lists:keyfind(J, 1, RBCs),
    {MyRBC, {send, Responses}} = reliable_broadcast:input(MyRBC0, Input),
    RBCMap = maps:from_list(lists:keyreplace(J, 1, RBCs, {J, MyRBC})),
    {Data#data{rbc=RBCMap}, {send, wrap({rbc, J}, Responses)}}.

handle_msg(Data = #data{n=N, f=F, secret_key=SK}, J, {{rbc, I}, RBCMsg}) ->
    case maps:find(I, Data#data.rbc) of
        {ok, RBC} ->
            case reliable_broadcast:handle_msg(RBC, J, RBCMsg) of
                {NewRBC, {send, ToSend}} ->
                    {Data#data{rbc=maps:put(I, NewRBC, Data#data.rbc)}, {send, wrap({rbc, I}, ToSend)}};
                {NewRBC, {result, Result}} ->
                    %% ok, start the BBA for this RBC
                    {BBA, {send, ToSend}} = bba:input(bba:init(SK, N, F), 1),
                    {Data#data{rbc=maps:put(I, NewRBC, Data#data.rbc),
                               bba=maps:put(I, BBA, Data#data.bba),
                               rbc_results=maps:put(I, Result, Data#data.rbc_results)},
                     {send, wrap({bba, I}, ToSend)}};
                {NewRBC, ok} ->
                    {Data#data{rbc=maps:put(I, NewRBC, Data#data.rbc)}, ok}
            end;
        error ->
            %% instanciate RBC and pass the message to it
            %% TODO make RBC message size part of the RBC messages so it can be variable
            {NewRBC, Response} = reliable_broadcast:handle_msg(reliable_broadcast:init(N, F, 512), J, RBCMsg),
            Reply = case Response of
                        {send, ToSend} ->
                            {send, wrap({rbc, I}, ToSend)};
                        _ ->
                            ok
                    end,
            {Data#data{rbc=maps:put(I, NewRBC, Data#data.rbc)}, Reply}
    end;
handle_msg(Data = #data{n=N, f=F, secret_key=SK}, J, {{bba, I}, BBAMsg}) ->
    BBA = maps:get(I, Data#data.bba),
    case bba:handle_msg(BBA, J, BBAMsg) of
        {NewBBA, {send, ToSend}} ->
            {Data#data{bba=maps:put(I, NewBBA, Data#data.bba)}, {send, wrap({bba, I}, ToSend)}};
        {NewBBA, {result, B}} ->
            NewBBAResults = maps:put(I, B == 1, Data#data.bba_results),
            %% upon delivery of value 1 from at least N − f instances of BA , provide input 0 to each instance of BA that has not yet been provided input.
            BBAsThatReturnedOne = length([ true || {_, true} <- maps:to_list(NewBBAResults)]),
            case BBAsThatReturnedOne == N - F andalso Data#data.done == false of
                true ->
                    %% send 0 to all BBAs that have not yet been provided input because their RBC has not completed
                    NewBBAsAndReplies = lists:foldl(fun(E, Acc) ->
                                                            case maps:is_key(E, Data#data.bba) of
                                                                false ->
                                                                    {BBA, {send, ToSend}} = bba:input(bba:init(SK, N, F), 0),
                                                                    [{{E, BBA}, wrap({bba, I}, ToSend)}|Acc];
                                                                true ->
                                                                    Acc
                                                            end
                                                    end, [], lists:seq(0, maps:size(Data#data.rbc) - 1)),
                    {NewBBAs, Replies} = lists:unzip(NewBBAsAndReplies),
                    {Data#data{bba=maps:merge(Data#data.bba, maps:from_list(NewBBAs)), bba_results=NewBBAResults, done=true}, {send, Replies}};
                false ->
                    %% check if all the BBA protocols have completed and all the RBC protocols have finished
                    Response = case sets:size(sets:from_list([maps:size(NewBBAResults), maps:size(Data#data.bba),
                                                              maps:size(Data#data.rbc_results), maps:size(Data#data.rbc)])) == 1 of
                                   true ->
                                       %% construct the list of which BBAs have succeeded
                                       BBAVector = [ X || {_, X} <- lists:keysort(1, maps:to_list(NewBBAResults))],
                                       %% return all the RBC values for which BBA has succeeded
                                       {result, [ Res || {true, {_, Res}} <- lists:zip(BBAVector, maps:to_list(Data#data.rbc_results))]};
                                   false ->
                                       ok
                               end,
                    {Data#data{bba=maps:put(I, NewBBA, Data#data.bba), bba_results=NewBBAResults}, Response}
            end;
        {NewBBA, ok} ->
            {Data#data{bba=maps:put(I, NewBBA, Data#data.bba)}, ok}
    end.

%% wrap a subprotocol's outbound messages with a protocol identifier
wrap(_, []) ->
    [];
wrap(Id, [{multicast, Msg}|T]) ->
    [{multicast, {Id, Msg}}|wrap(Id, T)];
wrap(Id, [{unicast, Dest, Msg}|T]) ->
    [{unicast, Dest, {Id, Msg}}|wrap(Id, T)].

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
                           States = [acs:init(Sk, N, F) || Sk <- PrivateKeys],
                           StatesWithId = lists:zip(lists:seq(0, length(States) - 1), States),
                           MixedList = lists:zip(Msgs, StatesWithId),
                           Res = lists:map(fun({Msg, {J, State}}) ->
                                                   {NewState, Result} = input(State, J, Msg),
                                                   {{J, NewState}, {J, Result}}
                                           end, MixedList),
                           {NewStates, Results} = lists:unzip(Res),
                           ConvergedResults = do_send_outer(Results, NewStates, sets:new()),
                           ?assertEqual(N, sets:size(ConvergedResults)),
                           DistinctResults = sets:from_list([BVal || {result, {_, BVal}} <- sets:to_list(ConvergedResults)]),
                           ?assertEqual(1, sets:size(DistinctResults)),
                           ?assertEqual(Msgs, lists:flatten(sets:to_list(DistinctResults))),
                           ok
                   end]}.

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
