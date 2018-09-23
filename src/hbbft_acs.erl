-module(hbbft_acs).

-export([init/4, input/2, handle_msg/3, serialize/1, deserialize/2, status/1]).

-record(rbc_state, {
          rbc_data :: hbbft_rbc:rbc_data(),
          result :: undefined | binary()
         }).

-record(bba_state, {
          bba_data :: hbbft_bba:bba_data(),
          input :: undefined | 0 | 1,
          result :: undefined | boolean()
         }).

-record(acs_data, {
          done = false :: boolean(),
          n :: pos_integer(),
          f :: non_neg_integer(),
          j :: non_neg_integer(),
          rbc = #{} :: #{non_neg_integer() => hbbft_acs:rbc_state()},
          bba = #{} :: #{non_neg_integer() => hbbft_acs:bba_state()}
         }).

-record(acs_serialized_data, {
          done = false :: boolean(),
          n :: pos_integer(),
          f :: non_neg_integer(),
          j :: non_neg_integer(),
          rbc = #{} :: #{non_neg_integer() => hbbft_acs:rbc_serialized_state()},
          bba = #{} :: #{non_neg_integer() => hbbft_acs:bba_serialized_state()}
         }).

-record(rbc_serialized_state, {
          rbc_data :: hbbft_rbc:rbc_data(),
          result :: undefined | binary()
         }).

-record(bba_serialized_state, {
          bba_data :: hbbft_bba:bba_serialized_data(),
          input :: undefined | 0 | 1,
          result :: undefined | boolean()
         }).

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

-spec status(acs_data()) -> map().
status(ACSData) ->
    #{acs_done => ACSData#acs_data.done,
      rbc => maps:map(fun(_K, #rbc_state{rbc_data=RBCData, result=R}) -> #{rbc => hbbft_rbc:status(RBCData), result => is_binary(R)} end, ACSData#acs_data.rbc),
      bba => maps:map(fun(_K, #bba_state{bba_data=BBAData, result=R, input=I}) -> #{bba => hbbft_bba:status(BBAData), result => R, input => I} end, ACSData#acs_data.bba)}.

-spec init(tpke_privkey:privkey(), pos_integer(), non_neg_integer(), non_neg_integer()) -> acs_data().
init(SK, N, F, J) ->
    %% instantiate all the RBCs
    %% J=leader, I=Pid
    RBCs = [{I, #rbc_state{rbc_data = hbbft_rbc:init(N, F, J, I)}} || I <- lists:seq(0, N-1)],
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
                                                                           defer |
                                                                           {send, [rbc_wrapped_output() | hbbft_utils:multicast(bba_msg())]} |
                                                                           {result, [{non_neg_integer(), binary()}]}}.
handle_msg(Data, J, {{rbc, I}, RBCMsg}) ->
    RBC = get_rbc(Data, I),
    case hbbft_rbc:handle_msg(RBC#rbc_state.rbc_data, J, RBCMsg) of
        {NewRBC, {send, ToSend}} ->
            {store_rbc_state(Data, I, NewRBC), {send, hbbft_utils:wrap({rbc, I}, ToSend)}};
        {NewRBC, {result, Result}} ->
            %% Figure4, Bullet2
            %% upon delivery of vj from RBCj, if input has not yet been provided to BAj, then provide input 1 to BAj
            NewData = store_rbc_result(store_rbc_state(Data, I, NewRBC), I, Result),
            case bba_has_had_input(maps:get(I, NewData#acs_data.bba)) of
                true ->
                    check_completion(NewData);
                false ->
                    %% ok, start the BBA for this RBC
                    BBA = get_bba(NewData, I),
                    case hbbft_bba:input(BBA#bba_state.bba_data, 1) of
                        {DoneBBA, ok} ->
                            {store_bba_state(NewData, I, DoneBBA), ok};
                        {NewBBA, {send, ToSend}} ->
                            {store_bba_input(store_bba_state(NewData, I, NewBBA), I, 1),
                            {send, hbbft_utils:wrap({bba, I}, ToSend)}}
                    end
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
            NewData = store_bba_state(store_bba_result(Data, I, B), I, NewBBA),
            %% Figure4, Bullet3
            %% upon delivery of value 1 from at least N − f instances of BA , provide input 0 to each instance of BA that has not yet been provided input.
            BBAsThatReturnedOne = successful_bba_count(NewData),
            case BBAsThatReturnedOne >= N - F andalso NewData#acs_data.done == false of
                true ->
                    %% send 0 to all BBAs that have not yet been provided input because their RBC has not completed
                    {NextData, Replies} = lists:foldl(fun(E, {DataAcc, MsgAcc}=Acc) ->
                                                              ThisBBA = get_bba(DataAcc, E),
                                                              case bba_has_had_input(ThisBBA) of
                                                                  false ->
                                                                      case hbbft_bba:input(ThisBBA#bba_state.bba_data, 0) of
                                                                          {FailedBBA, {send, ToSend}} ->
                                                                              {store_bba_input(store_bba_state(DataAcc, E, FailedBBA), E, 0), [hbbft_utils:wrap({bba, E}, ToSend)|MsgAcc]};
                                                                          {DoneBBA, ok} ->
                                                                              {store_bba_state(DataAcc, E, DoneBBA), MsgAcc}
                                                                      end;
                                                                  true ->
                                                                      Acc
                                                              end
                                                      end, {NewData, []}, lists:seq(0, N - 1)),
                    %% each BBA is independant, so the total ordering here is unimportant
                    {NextData#acs_data{done=true}, {send, lists:flatten(Replies)}};
                false ->
                    check_completion(NewData)
            end;
        {NewBBA, ok} ->
            {store_bba_state(Data, I, NewBBA), ok};
        {NewBBA, defer} ->
            %% BBA requested we defer this message for now
            {store_bba_state(Data, I, NewBBA), defer}
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

-spec get_bba(acs_data(), non_neg_integer()) -> bba_state().
get_bba(Data, I) ->
    maps:get(I, Data#acs_data.bba).

-spec bba_has_had_input(#bba_state{}) -> boolean().
bba_has_had_input(#bba_state{input=Input}) ->
    Input /= undefined.

-spec get_bba_result(acs_data(), non_neg_integer()) -> undefined | boolean().
get_bba_result(Data, I) ->
    BBA = get_bba(Data, I),
    BBA#bba_state.result.

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

-spec serialize(acs_data()) -> acs_serialized_data().
serialize(#acs_data{done=Done, n=N, f=F, j=J, rbc=RBCMap, bba=BBAMap}) ->
    #acs_serialized_data{done=Done, n=N, f=F, j=J, rbc=serialize_state(RBCMap, rbc), bba=serialize_state(BBAMap, bba)}.

-spec deserialize(acs_serialized_data(), tpke_privkey:privkey()) -> acs_data().
deserialize(#acs_serialized_data{done=Done, n=N, f=F, j=J, rbc=RBCMap, bba=BBAMap}, SK) ->
    #acs_data{done=Done, n=N, f=F, j=J, rbc=deserialize_state(RBCMap, rbc), bba=deserialize_state(BBAMap, bba, SK)}.

%% Helper functions for serialization/deserialization
-spec serialize_state(#{non_neg_integer() => rbc_state() | bba_state()}, rbc | bba) -> #{}.
serialize_state(State, rbc) ->
    maps:map(fun(_K, V) -> serialize_rbc_state(V) end, State);
serialize_state(State, bba) ->
    maps:map(fun(_K, V) -> serialize_bba_state(V) end, State).

-spec deserialize_state(#{non_neg_integer() => rbc_serialized_state()}, rbc) -> #{}.
deserialize_state(State, rbc) ->
    maps:map(fun(_K, V) -> deserialize_rbc_state(V) end, State).

-spec deserialize_state(#{non_neg_integer() => bba_serialized_state()}, bba, tpke_privkey:privkey()) -> #{}.
deserialize_state(State, bba, SK) ->
    maps:map(fun(_K, V) -> deserialize_bba_state(V, SK) end, State).

-spec serialize_rbc_state(rbc_state()) -> rbc_serialized_state().
serialize_rbc_state(#rbc_state{rbc_data=RBCData, result=Result}) ->
    #rbc_serialized_state{rbc_data=RBCData, result=Result}.

-spec deserialize_rbc_state(rbc_serialized_state()) -> rbc_state().
deserialize_rbc_state(#rbc_serialized_state{rbc_data=RBCData, result=Result}) ->
    #rbc_state{rbc_data=RBCData, result=Result}.

-spec serialize_bba_state(bba_state()) -> bba_serialized_state().
serialize_bba_state(#bba_state{bba_data=BBAData, input=Input, result=Result}) ->
    #bba_serialized_state{bba_data=hbbft_bba:serialize(BBAData), input=Input, result=Result}.

-spec deserialize_bba_state(bba_serialized_state(), tpke_privkey:privkey()) -> bba_state().
deserialize_bba_state(#bba_serialized_state{bba_data=BBAData, input=Input, result=Result}, SK) ->
    #bba_state{bba_data=hbbft_bba:deserialize(BBAData, SK), input=Input, result=Result}.
