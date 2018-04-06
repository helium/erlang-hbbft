-module(bba).

-export([init/3, input/2, handle_msg/3]).

-record(data, {
          state = init :: init | waiting | done,
          round = 0,
          secret_key,
          coin,
          est :: 0 | 1,
          f :: pos_integer(),
          n :: pos_integer(),
          witness = sets:new() :: sets:set({non_neg_integer(), 0 | 1}),
          aux_witness = sets:new() :: sets:set({non_neg_integer(), 0 | 1}),
          broadcasted = sets:new() :: sets:set(0 | 1),
          bin_values = sets:new() :: set:set(0 | 1)
         }).

%-type bval_msg() :: {bval, {pos_integer(), 0 | 1}}.

%-type multicast() :: {multicast, bval_msg()}.

init(SK, N, F) ->
    #data{secret_key=SK, n=N, f=F}.

input(Data = #data{state=init}, BInput) ->
    {Data#data{est = BInput}, {send, [{multicast, {bval, BInput}}]}}.

handle_msg(Data, J, {bval, V}) ->
    bval(Data, J, V);
handle_msg(Data, J, {aux, V}) ->
    aux(Data, J, V);
handle_msg(Data, J, {coin, CMsg}) ->
    %% dispatch the message to the nested coin protocol
    ok.

%-spec bv_broadcast(#data{}, sets:set({non_neg_integer(), 0 | 1})) -> {#data{}, {send, broadcast()} | {error, not_enough_witnesses}}.
bval(Data=#data{n=N, f=F}, Id, V) ->
    %% add to witnesses
    Witness = sets:add_element({Id, V}, Data#data.witness),
    WitnessCount = lists:sum([ 1 || {_, Val} <- sets:to_list(Witness), V == Val ]),
    case WitnessCount >= F+1 andalso sets:is_element(V, Data#data.broadcasted) == false of
        true ->
            %% add to broadcasted
            NewData = Data#data{witness=Witness,
                                broadcasted=sets:add_element(V, Data#data.broadcasted)},
            {NewData , {send, [{multicast, {bval, V}}]}};
        false ->
            case WitnessCount >= 2*F+1 of
                true ->
                    %% add to binvalues
                    NewData = Data#data{witness=Witness,
                                        bin_values=sets:add_element(V, Data#data.bin_values)},
                    %% XXX How many times do we send AUX per round? I think just once
                    Random = lists:nth(rand:uniform(sets:size(NewData#data.bin_values), sets:from_list(NewData#data.bin_values))),
                    AuxSend = [{multicast, {aux, Random}}],

                    %% check if we've received at least N - F AUX messages where the values in the AUX messages are member of bin_values
                    case sets:size(sets:filter(fun({_, X}) -> sets:is_element(X, NewData#data.bin_values) end, NewData#data.aux_witness)) >= N - F of
                        true when NewData#data.coin == undefined ->
                            %% instanciate the common coin
                            %% TODO need more entropy for the SID
                            {CoinData, {send, ToSend}} = common_coin:get_coin(common_coin:init(NewData#data.secret_key, {NewData#data.round}, N, F)),
                            {NewData#data{coin=CoinData} , {send, [ToSend|AuxSend]}};
                        _ ->
                            {NewData, {send, AuxSend}}
                    end
            end
    end.

aux(Data = #data{n=N, f=F}, Id, V) ->
    Witness = sets:add_element({Id, V}, Data#data.aux_witness),
    NewData = Data#data{aux_witness = Witness},
    %% check if we've received at least N - F AUX messages where the values in the AUX messages are member of bin_values
    case sets:size(sets:filter(fun({_, X}) -> sets:is_element(X, NewData#data.bin_values) end, NewData#data.aux_witness)) >= N - F of
        true when NewData#data.coin == undefined ->
            %% instanciate the common coin
            %% TODO need more entropy for the SID
            {CoinData, {send, ToSend}} = common_coin:get_coin(common_coin:init(NewData#data.secret_key, {NewData#data.round}, N, F)),
            {NewData#data{coin=CoinData} , {send, ToSend}};
        _ ->
            {NewData, ok}
    end.

