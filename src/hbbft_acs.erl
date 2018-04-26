-module(hbbft_acs).

-include_lib("hbbft_acs.hrl").

-export([init/4, input/2, handle_msg/3, serialize_acs_data/1]).

-type acs_data() :: #acs_data{}.
-type acs_serialized_data() :: #acs_serialized_data{}.
-type rbc_state() :: #rbc_state{}.
-type rbc_serialized_state() :: #rbc_serialized_state{}.
-type bba_state() :: #bba_state{}.
-type bba_serialized_state() :: #bba_serialized_state{}.

-type bba_msg() :: {{bba, non_neg_integer()}, hbbft_bba:msgs()}.
-type rbc_msg() :: {{rbc, non_neg_integer()}, hbbft_rbc:msgs()}.
-type rbc_wrapped_output() :: hbbft_utils:unicast({{rbc, non_neg_integer()}, hbbft_rbc:val_msg()}) | hbbft_utils:multicast({{rbc, non_neg_integer()}, hbbft_rbc:echo_msg() | hbbft_rbc:ready_msg()}).
-type msgs() :: bba_msg() | rbc_msg().

-export_type([acs_data/0, msgs/0, bba_msg/0, acs_serialized_data/0, bba_state/0, rbc_state/0, bba_serialized_state/0, rbc_serialized_state/0]).

-spec init(tpke_privkey:privkey(), pos_integer(), non_neg_integer(), non_neg_integer()) -> acs_data().
init(SK, N, F, J) ->
    %% instantiate all the RBCs
    RBCs = [{I, #rbc_state{rbc_data = hbbft_rbc:init(N, F)}} || I <- lists:seq(0, N-1)],
    %% instantiate all the BBAs
    BBAs = [{I, #bba_state{bba_data = hbbft_bba:init(SK, N, F)}} || I <- lists:seq(0, N-1)],
    #acs_data{n=N, f=F, j=J, rbc=maps:from_list(RBCs), bba=maps:from_list(BBAs)}.

%% Figure4, Bullet1
%% upon receiving input vi , input vi to RBCi
-spec input(acs_data(), binary()) -> {acs_data(), {send, [rbc_wrapped_output()]}}.
input(Data, Input) ->
    %% input the message to our RBC
    MyRBC0 = get_rbc(Data, Data#acs_data.j),
    {MyRBC, {send, Responses}} = hbbft_rbc:input(MyRBC0#rbc_state.rbc_data, Input),
    {store_rbc_state(Data, Data#acs_data.j, MyRBC), {send, hbbft_utils:wrap({rbc, Data#acs_data.j}, Responses)}}.

-spec handle_msg(acs_data(), non_neg_integer(), rbc_msg() | bba_msg()) -> {acs_data(), ok |
                                                                           {send, [rbc_wrapped_output() | hbbft_utils:multicast(bba_msg())]} |
                                                                           {result, [{non_neg_integer(), binary()}]}}.
handle_msg(Data, J, {{rbc, I}, RBCMsg}) ->
    RBC = get_rbc(Data, I),
    io:format("~p RBC message for ~p ~p~n", [Data#acs_data.j, I, element(1, RBCMsg)]),
    case hbbft_rbc:handle_msg(RBC#rbc_state.rbc_data, J, RBCMsg) of
        {NewRBC, {send, ToSend}} ->
            {store_rbc_state(Data, I, NewRBC), {send, hbbft_utils:wrap({rbc, I}, ToSend)}};
        {NewRBC, {result, Result}} ->
            %% Figure4, Bullet2
            %% upon delivery of vj from RBCj, if input has not yet been provided to BAj, then provide input 1 to BAj
            io:format("~p RBC returned for ~p~n", [Data#acs_data.j, I]),
            NewData = store_rbc_result(store_rbc_state(Data, I, NewRBC), I, Result),
            case bba_has_had_input(maps:get(I, Data#acs_data.bba)) of
                true ->
                    check_completion(NewData);
                false ->
                    %% ok, start the BBA for this RBC
                    BBA = get_bba(NewData, I),
                    {NewBBA, {send, ToSend}} = hbbft_bba:input(BBA#bba_state.bba_data, 1),
                    {store_bba_input(store_bba_state(NewData, I, NewBBA), I, 1),
                     {send, hbbft_utils:wrap({bba, I}, ToSend)}}
            end;
        {NewRBC, ok} ->
            {store_rbc_state(Data, I, NewRBC), ok}
    end;
handle_msg(Data = #acs_data{n=N, f=F}, J, {{bba, I}, BBAMsg}) ->
    BBA = get_bba(Data, I),
    case hbbft_bba:handle_msg(BBA#bba_state.bba_data, J, BBAMsg) of
        {NewBBA, {send, ToSend}} ->
            {store_bba_state(Data, I, NewBBA), {send, hbbft_utils:wrap({bba, I}, ToSend)}};
        {NewBBA, {result, B}} ->
            io:format("~p BBA ~p returned ~p~n", [Data#acs_data.j, I, B]),
            NewData = store_bba_state(store_bba_result(Data, I, B), I, NewBBA),
            %% Figure4, Bullet3
            %% upon delivery of value 1 from at least N − f instances of BA , provide input 0 to each instance of BA that has not yet been provided input.
            BBAsThatReturnedOne = successful_bba_count(NewData),
            io:format("~p ~p BBAs completed, ~p returned one, ~p needed~n", [Data#acs_data.j, completed_bba_count(NewData), BBAsThatReturnedOne, N - F]),
            case BBAsThatReturnedOne >= N - F andalso NewData#acs_data.done == false of
                true ->
                    io:format("~b Enough BBAs (~b/~b) completed, zeroing the rest~n", [Data#acs_data.j, BBAsThatReturnedOne, N]),
                    %% send 0 to all BBAs that have not yet been provided input because their RBC has not completed
                    {NextData, Replies} = lists:foldl(fun(E, {DataAcc, MsgAcc}=Acc) ->
                                                              ThisBBA = get_bba(DataAcc, E),
                                                              case bba_has_had_input(ThisBBA) of
                                                                  false ->
                                                                      {FailedBBA, {send, ToSend}} = hbbft_bba:input(ThisBBA#bba_state.bba_data, 0),
                                                                      io:format("~p Sending BBA ~p zero~n", [Data#acs_data.j, E]),
                                                                      {store_bba_input(store_bba_state(Data, E, FailedBBA), E, 0), [hbbft_utils:wrap({bba, E}, ToSend)|MsgAcc]};
                                                                  true ->
                                                                      Acc
                                                              end
                                                      end, {NewData, []}, lists:seq(0, N - 1)),
                    {NextData#acs_data{done=true}, {send, lists:flatten(Replies)}};
                false ->
                    check_completion(NewData)
            end;
        {NewBBA, ok} ->
            {store_bba_state(Data, I, NewBBA), ok}
    end.

check_completion(Data = #acs_data{n=N}) ->
    %% Figure4, Bullet4
    %% once all instances of BA have completed, let C⊂[1..N] be the indexes of each BA that delivered 1.
    %% Wait for the output vj for each RBCj such that j∈C. Finally output ∪j∈Cvj.
    %% Note that this means if a BBA has returned 0, we don't need to wait for the corresponding RBC.
    case lists:all(fun({E, RBC}) -> get_bba_result(Data, E) == false orelse rbc_completed(RBC) end, maps:to_list(Data#acs_data.rbc)) andalso
         lists:all(fun(BBA) -> bba_completed(BBA) end, maps:values(Data#acs_data.bba)) of
        true ->
            ResultVector = [ {E, get_rbc_result(Data, E)} || E <- lists:seq(0, N-1), get_bba_result(Data, E) ],
            {Data, {result, ResultVector}};
        false ->
            {Data, ok}
    end.

-spec rbc_completed(rbc_state()) -> boolean().
rbc_completed(#rbc_state{result=Result}) ->
    Result /= undefined.

-spec bba_completed(bba_state()) -> boolean().
bba_completed(#bba_state{input=Input, result=Result}) ->
    Input /= undefined andalso Result /= undefined.

-spec successful_bba_count(acs_data()) -> non_neg_integer(). %% successful_bba_count can be 0?
successful_bba_count(Data) ->
    lists:sum([ 1 || BBA <- maps:values(Data#acs_data.bba), BBA#bba_state.result]).

-spec completed_bba_count(acs_data()) -> non_neg_integer(). %% completed_bba_count cannot be 0
completed_bba_count(Data) ->
    lists:sum([ 1 || BBA <- maps:values(Data#acs_data.bba), BBA#bba_state.result /= undefined]).

-spec get_bba(acs_data(), non_neg_integer()) -> bba_state().
get_bba(Data, I) ->
    maps:get(I, Data#acs_data.bba).

-spec bba_has_had_input(#bba_state{}) -> boolean().
bba_has_had_input(#bba_state{input=Input}) ->
    Input /= undefined.

-spec get_bba_result(acs_data(), non_neg_integer()) -> undefined | boolean().
get_bba_result(Data, I) ->
    RBC = get_bba(Data, I),
    RBC#bba_state.result.

-spec store_bba_state(acs_data(), non_neg_integer(), hbbft_bba:bba_data()) -> acs_data().
store_bba_state(Data, I, State) ->
    BBA = get_bba(Data, I),
    Data#acs_data{bba = maps:put(I, BBA#bba_state{bba_data=State}, Data#acs_data.bba)}.

-spec store_bba_input(acs_data(), non_neg_integer(), 0 | 1) -> acs_data().
store_bba_input(Data, I, Input) ->
    BBA = get_bba(Data, I),
    Data#acs_data{bba = maps:put(I, BBA#bba_state{input=Input}, Data#acs_data.bba)}.

-spec store_bba_result(acs_data(), non_neg_integer(), 0 | 1) -> acs_data().
store_bba_result(Data, I, Result) ->
    BBA = get_bba(Data, I),
    Data#acs_data{bba = maps:put(I, BBA#bba_state{result=(Result == 1)}, Data#acs_data.bba)}.

-spec get_rbc(acs_data(), non_neg_integer()) -> rbc_state().
get_rbc(Data, I) ->
    maps:get(I, Data#acs_data.rbc).

-spec get_rbc_result(acs_data(), non_neg_integer()) -> undefined | binary().
get_rbc_result(Data, I) ->
    RBC = get_rbc(Data, I),
    RBC#rbc_state.result.

-spec store_rbc_state(acs_data(), non_neg_integer(), hbbft_rbc:rbc_data()) -> acs_data().
store_rbc_state(Data, I, State) ->
    RBC = get_rbc(Data, I),
    Data#acs_data{rbc = maps:put(I, RBC#rbc_state{rbc_data=State}, Data#acs_data.rbc)}.

-spec store_rbc_result(acs_data(), non_neg_integer(), undefined | binary()) -> acs_data().
store_rbc_result(Data, I, Result) ->
    RBC = get_rbc(Data, I),
    Data#acs_data{rbc = maps:put(I, RBC#rbc_state{result=Result}, Data#acs_data.rbc)}.

-spec serialize_acs_data(acs_data()) -> acs_serialized_data().
serialize_acs_data(#acs_data{done=Done, n=N, f=F, j=J, rbc=RBCMap, bba=BBAMap}) ->
    SerializedRBCMap = maps:map(fun(_K, V) -> serialize_rbc_state(V) end, RBCMap),
    SerializedBBAMap = maps:map(fun(_K, V) -> serialize_bba_state(V) end, BBAMap),
    #acs_serialized_data{done=Done, n=N, f=F, j=J, rbc=SerializedRBCMap, bba=SerializedBBAMap}.

-spec serialize_rbc_state(rbc_state()) -> rbc_serialized_state().
serialize_rbc_state(#rbc_state{rbc_data=RBCData, result=Result}) ->
    #rbc_serialized_state{rbc_data=hbbft_rbc:serialize_rbc_data(RBCData), result=Result}.

-spec serialize_bba_state(bba_state()) -> bba_serialized_state().
serialize_bba_state(#bba_state{bba_data=BBAData, input=Input, result=Result}) ->
    #bba_serialized_state{bba_data=hbbft_bba:serialize_bba_data(BBAData), input=Input, result=Result}.

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
