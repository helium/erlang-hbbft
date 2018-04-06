-module(bba).

-export([init/3, input/2, handle_msg/3]).

-record(data, {
          state = init :: init | waiting | done,
          round = 0,
          secret_key,
          coin,
          est :: 0 | 1,
          output,
          f :: pos_integer(),
          n :: pos_integer(),
          witness = sets:new() :: sets:set({non_neg_integer(), 0 | 1}),
          aux_witness = sets:new() :: sets:set({non_neg_integer(), 0 | 1}),
          aux_sent = false,
          broadcasted = sets:new() :: sets:set(0 | 1),
          bin_values = sets:new() :: set:set(0 | 1)
         }).

%-type bval_msg() :: {bval, {pos_integer(), 0 | 1}}.

%-type multicast() :: {multicast, bval_msg()}.

init(SK, N, F) ->
    #data{secret_key=SK, n=N, f=F}.

input(Data = #data{state=init}, BInput) ->
    {Data#data{est = BInput}, {send, [{multicast, {bval, Data#data.round, BInput}}]}}.

handle_msg(Data = #data{round=R}, J, {bval, R, V}) ->
    bval(Data = #data{round=R}, J, V);
handle_msg(Data = #data{round=R}, J, {aux, R, V}) ->
    aux(Data, J, V);
handle_msg(Data = #data{round=R}, J, {coin, R, CMsg}) ->
    %% dispatch the message to the nested coin protocol
    case common_coin:handle_msg(Data#data.coin, J, CMsg) of
        {NewCoin, {result, Result}} ->
            %% ok, we've obtained the common coin
            case sets:size(Data#data.bin_values) == 1 of
                true ->
                    %% if vals = {b}, then
                    [B] = sets:to_list(Data#data.bin_values),
                    Output = case Result rem 2 == B of
                                 true ->
                                     %% if (b = s%2) then output b
                                     B;
                                 false ->
                                     undefined
                             end,
                    case B == Result rem 2 andalso Data#data.output == B of
                        true ->
                            %% we are done
                            {Data, {result, B}};
                        false ->
                            %% increment round and continue
                            NewData = init(Data#data.secret_key, Data#data.n, Data#data.f),
                            input(NewData#data{round=Data#data.round + 1, output=Output}, B)
                    end;
                false ->
                    %% else estr+1 := s%2
                    B = Result rem 2,
                    NewData = init(Data#data.secret_key, Data#data.n, Data#data.f),
                    input(NewData#data{round=Data#data.round + 1}, B)
            end;
        {NewCoin, {send, Messages}} ->
            {Data#data{coin=NewCoin}, {send, wrap(coin, Messages)}};
        {NewCoin, ok} ->
            {Data#data{coin=NewCoin}, ok}
    end.

%-spec bv_broadcast(#data{}, sets:set({non_neg_integer(), 0 | 1})) -> {#data{}, {send, broadcast()} | {error, not_enough_witnesses}}.
bval(Data=#data{n=N, f=F}, Id, V) ->
    %% add to witnesses
    Witness = sets:add_element({Id, V}, Data#data.witness),
    WitnessCount = lists:sum([ 1 || {_, Val} <- sets:to_list(Witness), V == Val ]),
    {NewData, ToSend} = case WitnessCount >= F+1 andalso sets:is_element(V, Data#data.broadcasted) == false of
                            true ->
                                %% add to broadcasted
                                NewData0 = Data#data{witness=Witness,
                                                    broadcasted=sets:add_element(V, Data#data.broadcasted)},
                                {NewData0, [{multicast, {bval, Data#data.round, V}}]};
                            false ->
                                {Data, []}
                        end,

    case WitnessCount >= 2*F+1 of
        true ->
            %% add to binvalues
            NewData2 = Data#data{witness=Witness,
                                 bin_values=sets:add_element(V, NewData#data.bin_values)},
            {NewData3, ToSend2} = case NewData2#data.aux_sent == false of
                          true ->
                              %% XXX How many times do we send AUX per round? I think just once
                              Random = lists:nth(rand:uniform(sets:size(NewData#data.bin_values), sets:from_list(NewData#data.bin_values))),
                              {NewData2#data{aux_sent = true}, [{multicast, {aux, NewData2#data.round, Random}}|ToSend]};
                          false ->
                              {NewData2, ToSend}
                      end,
            %% check if we've received at least N - F AUX messages where the values in the AUX messages are member of bin_values
            case sets:size(sets:filter(fun({_, X}) -> sets:is_element(X, NewData3#data.bin_values) end, NewData3#data.aux_witness)) >= N - F of
                true when NewData3#data.coin == undefined ->
                    %% instanciate the common coin
                    %% TODO need more entropy for the SID
                    {CoinData, {send, CoinSend}} = common_coin:get_coin(common_coin:init(NewData3#data.secret_key, {NewData3#data.round}, N, F)),
                    {NewData3#data{coin=CoinData} , {send, [wrap(coin, CoinSend)|ToSend2]}};
                _ ->
                    {NewData3, {send, ToSend2}}
            end;
        false ->
            {NewData, {send, ToSend}}
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

%% wrap a subprotocol's outbound messages with a protocol identifier
wrap(_, []) ->
    [];
wrap(Id, [{multicast, Msg}|T]) ->
    [{multicast, {Id, Msg}}|wrap(Id, T)];
wrap(Id, [{unicast, Dest, Msg}|T]) ->
    [{unicast, Dest, {Id, Msg}}|wrap(Id, T)].

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

kill(Data) ->
    Data#data{state=done}.

init_test() ->
    N = 5,
    F = 1,
    dealer:start_link(N, F+1, 'SS512'),
    {ok, PubKey, PrivateKeys} = dealer:deal(),
    gen_server:stop(dealer),
    States = [bba:init(Sk, N, F) || Sk <- PrivateKeys],
    StatesWithId = lists:zip(lists:seq(0, length(States) - 1), States),
    %% all valid members should call get_coin
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = input(State, 1),
                            {{J, NewState}, {J, Result}}
                    end, StatesWithId),
    {NewStates, Results} = lists:unzip(Res),
    ConvergedResults = do_send_outer(Results, NewStates, []),
    %% everyone should converge
    ?assertEqual(N, length(ConvergedResults)),
    ok.

do_send_outer([], _, Acc) ->
    Acc;
do_send_outer([{result, {Id, Result}} | T], Pids, Acc) ->
    do_send_outer(T, Pids, [{result, {Id, Result}} | Acc]);
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
