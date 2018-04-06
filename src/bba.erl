-module(bba).

-export([init/1, bv_broadcast/2]).

-record(data, {
          state = waiting :: waiting | done,
          f :: pos_integer(),
          witnesses = sets:new() :: sets:set({non_neg_integer(), 0 | 1}),
          broadcasted = sets:new() :: sets:set(0 | 1),
          bin_values = sets:new() :: set:set(0 | 1)
         }).

-type bval_msg() :: {bval, {pos_integer(), 0 | 1}}.

-type broadcast() :: {broadcast, bval_msg()}.

init(F) ->
    Data = #data{f=F},
    {ok, Data}.

-spec bv_broadcast(#data{}, sets:set({non_neg_integer(), 0 | 1})) -> {#data{}, {send, broadcast()} | {error, not_enough_witnesses}}.
bv_broadcast(Data=#data{f=F}, {Id, V}) ->
    case sets:size(Data#data.witnesses) >= F+1 andalso sets:is_element(V, Data#data.broadcasted) == false of
        true ->
            %% broadcast
            %% add to witnesses
            %% add to broadcasted
            NewData = Data#data{state=waiting,
                                witnesses=sets:add_element({Id, V}, Data#data.witnesses),
                                broadcasted=sets:add_element(V, Data#data.broadcasted)},
            {NewData , {send, broadcast, {bval, {Id, V}}}};
        false ->
            %% add to witnesses
            %% keep waiting
            NewData = Data#data{state=waiting,
                                witnesses=sets:add_element({Id, V}, Data#data.witnesses)},
            {NewData, send, error, not_enough_witnesses}
    end;
bv_broadcast(Data=#data{state=waiting, f=F}, {Id, V}) ->
    case sets:size(Data#data.witnesses) >= 2*F+1 andalso sets:is_element(V, Data#data.bin_values) == false of
        true ->
            %% add to witnesses?
            %% add to binvalues
            NewData = Data#data{state=done,
                                witnesses=sets:add_element({Id, V}, Data#data.witnesses),
                                bin_values=sets:add_element(V, Data#data.bin_values)},
            {NewData , {send, done, {bval, {Id, V}}}};
        false ->
            %% keep waiting
            {Data#data{state=waiting}, send, error, not_enough_witnesses}
    end;
bv_broadcast(Data=#data{state=done}, _) -> Data#data.bin_values.
