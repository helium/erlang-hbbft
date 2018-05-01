-module(hbbft_bba).

-include_lib("hbbft_bba.hrl").

-export([init/3, input/2, handle_msg/3, serialize/1, deserialize/2]).

-type bba_data() :: #bba_data{}.
-type bba_serialized_data() :: #bba_serialized_data{}.

-type bval_msg() :: {bval, non_neg_integer(), 0 | 1}.
-type aux_msg() :: {aux, non_neg_integer(), 0 | 1}.
-type coin_msg() :: {{coin, non_neg_integer()}, hbbft_cc:share_msg()}.
-type msgs() :: bval_msg() | aux_msg() | coin_msg().

-export_type([bba_data/0, bba_serialized_data/0, bval_msg/0, aux_msg/0, coin_msg/0, msgs/0]).

-spec init(tpke_privkey:privkey(), pos_integer(), non_neg_integer()) -> bba_data().
init(SK, N, F) ->
    #bba_data{secret_key=SK, n=N, f=F}.

%% upon receiving input binput , set est0 := binput and proceed as
%% follows in consecutive epochs, with increasing labels r:
%% – multicast BVALr (estr )
%% – bin_values  {}
-spec input(bba_data(), 0 | 1) -> {bba_data(), ok | {send, [hbbft_utils:multicast(bval_msg())]}}.
input(Data = #bba_data{state=init}, BInput) ->
    {Data#bba_data{est = BInput}, {send, [{multicast, {bval, Data#bba_data.round, BInput}}]}};
input(Data = #bba_data{state=done}, _BInput) ->
    {Data, ok}.

-spec handle_msg(bba_data(), non_neg_integer(),
                 coin_msg() |
                 bval_msg() |
                 aux_msg()) -> {bba_data(), ok} |
                               {bba_data(), {send, [hbbft_utils:multicast(bval_msg() | aux_msg() | coin_msg())]}} |
                               {bba_data(), {result, 0 | 1}}.
handle_msg(Data = #bba_data{state=done}, _J, _BInput) ->
    {Data, ok};
handle_msg(Data = #bba_data{round=R}, J, {bval, R, V}) ->
    bval(Data, J, V);
handle_msg(Data = #bba_data{round=_R}, J, {aux, _R, V}) ->
    aux(Data, J, V);
handle_msg(Data = #bba_data{round=R, coin=Coin}, J, {{coin, R}, CMsg}) when Coin /= undefined ->
    %% dispatch the message to the nested coin protocol
    case hbbft_cc:handle_msg(Data#bba_data.coin, J, CMsg) of
        {_NewCoin, {result, Result}} ->
            %% ok, we've obtained the common coin
            case count(Data#bba_data.bin_values) == 1 of
                true ->
                    %% if vals = {b}, then
                    B = val(Data#bba_data.bin_values),
                    Output = case Result rem 2 == B of
                                 true ->
                                     %% if (b = s%2) then output b
                                     B;
                                 false ->
                                     undefined
                             end,
                    case B == Result rem 2 andalso Data#bba_data.output == B of
                        true ->
                            %% we are done
                            {Data, {result, B}};
                        false ->
                            %% increment round and continue
                            NewData = init(Data#bba_data.secret_key, Data#bba_data.n, Data#bba_data.f),
                            input(NewData#bba_data{round=Data#bba_data.round + 1, output=Output}, B)
                    end;
                false ->
                    %% else estr+1 := s%2
                    B = Result rem 2,
                    NewData = init(Data#bba_data.secret_key, Data#bba_data.n, Data#bba_data.f),
                    input(NewData#bba_data{round=Data#bba_data.round + 1}, B)
            end;
        {NewCoin, ok} ->
            {Data#bba_data{coin=NewCoin}, ok}
    end;
handle_msg(Data, _J, _Msg) ->
    {Data, ok}.

%% – upon receiving BVALr (b) messages from f + 1 nodes, if
%% BVALr (b) has not been sent, multicast BVALr (b)
-spec bval(bba_data(), non_neg_integer(), 0 | 1) -> {bba_data(), {send, [hbbft_utils:multicast(aux_msg() | coin_msg())]}}.
bval(Data=#bba_data{n=N, f=F}, Id, V) ->
    %% add to witnesses
    Witness = maps:put(Id, V, Data#bba_data.witness),
    WitnessCount = lists:sum([ 1 || {_, Val} <- maps:to_list(Witness), V == Val ]),

    {NewData, ToSend} = case WitnessCount >= F+1 andalso not has(V, Data#bba_data.broadcasted) of
                            true ->
                                %% add to broadcasted
                                NewData0 = Data#bba_data{witness=Witness,
                                                         broadcasted=add(V, Data#bba_data.broadcasted)},
                                {NewData0, [{multicast, {bval, Data#bba_data.round, V}}]};
                            false ->
                                {Data#bba_data{witness=Witness}, []}
                        end,

    %% - upon receiving BVALr (b) messages from 2 f + 1 nodes,
    %% bin_values_r := bin_valuesr ∪ {b}
    case WitnessCount >= 2*F+1 of
        true ->
            %% add to binvalues
            NewData2 = Data#bba_data{witness=Witness,
                                     bin_values=add(V, NewData#bba_data.bin_values)},
            {NewData3, ToSend2} = case NewData2#bba_data.aux_sent == false of
                                      true ->
                                          %% XXX How many times do we send AUX per round? I think just once
                                          Random = rand_val(NewData2#bba_data.bin_values),
                                          {NewData2#bba_data{aux_sent = true}, [{multicast, {aux, NewData2#bba_data.round, Random}} | ToSend]};
                                      false ->
                                          {NewData2, ToSend}
                                  end,

            case check_n_minus_f_aux_messages(N, F, NewData3) of
                true when NewData3#bba_data.coin == undefined ->
                    %% instantiate the common coin
                    %% TODO need more entropy for the SID
                    {CoinData, {send, CoinSend}} = hbbft_cc:get_coin(hbbft_cc:init(NewData3#bba_data.secret_key, term_to_binary({NewData3#bba_data.round}), N, F)),
                    {NewData3#bba_data{coin=CoinData}, {send, hbbft_utils:wrap({coin, Data#bba_data.round}, CoinSend) ++ ToSend2}};
                _ ->
                    {NewData3, {send, ToSend2}}
            end;
        false ->
            {NewData, {send, ToSend}}
    end.

-spec aux(bba_data(), non_neg_integer(), 0 | 1) -> {bba_data(), ok | {send, [hbbft_utils:multicast(coin_msg())]}}.
aux(Data = #bba_data{n=N, f=F}, Id, V) ->
    Witness = maps:put(Id, V, Data#bba_data.aux_witness),
    NewData = Data#bba_data{aux_witness = Witness},
    case check_n_minus_f_aux_messages(N, F, NewData) of
        true when NewData#bba_data.coin == undefined ->
            %% instantiate the common coin
            %% TODO need more entropy for the SID
            {CoinData, {send, ToSend}} = hbbft_cc:get_coin(hbbft_cc:init(NewData#bba_data.secret_key, term_to_binary({NewData#bba_data.round}), N, F)),
            {NewData#bba_data{coin=CoinData}, {send, hbbft_utils:wrap({coin, Data#bba_data.round}, ToSend)}};
        _ ->
            {NewData, ok}
    end.

-spec serialize(bba_data()) -> bba_serialized_data().
serialize(#bba_data{state=State,
                    round=Round,
                    coin=Coin,
                    est=Est,
                    output=Output,
                    f=F,
                    n=N,
                    witness=Witness,
                    aux_witness=AuxWitness,
                    aux_sent=AuxSent,
                    broadcasted=Broadcasted,
                    bin_values=BinValues}) ->
    NewCoin = case Coin of
                  undefined -> undefined;
                  _ -> hbbft_cc:serialize(Coin)
              end,
    #bba_serialized_data{state=State,
                         round=Round,
                         coin=NewCoin,
                         est=Est,
                         output=Output,
                         f=F,
                         n=N,
                         witness=Witness,
                         aux_witness=AuxWitness,
                         aux_sent=AuxSent,
                         broadcasted=Broadcasted,
                         bin_values=BinValues}.


-spec deserialize(bba_serialized_data(), tpke_privkey:privkey()) -> bba_data().
deserialize(#bba_serialized_data{state=State,
                                 round=Round,
                                 coin=Coin,
                                 est=Est,
                                 output=Output,
                                 f=F,
                                 n=N,
                                 witness=Witness,
                                 aux_witness=AuxWitness,
                                 aux_sent=AuxSent,
                                 broadcasted=Broadcasted,
                                 bin_values=BinValues}, SK) ->
    NewCoin = case Coin of
                  undefined -> undefined;
                  _ -> hbbft_cc:deserialize(Coin, SK)
              end,
    #bba_data{state=State,
              secret_key=SK,
              round=Round,
              coin=NewCoin,
              est=Est,
              output=Output,
              f=F,
              n=N,
              witness=Witness,
              aux_witness=AuxWitness,
              aux_sent=AuxSent,
              broadcasted=Broadcasted,
              bin_values=BinValues}.


%% helper functions
-spec check_n_minus_f_aux_messages(pos_integer(), non_neg_integer(), bba_data()) -> boolean().
check_n_minus_f_aux_messages(N, F, Data) ->
    %% check if we've received at least N - F AUX messages where the values in the AUX messages are member of bin_values
    maps:size(maps:filter(fun(_, X) -> has(X, Data#bba_data.bin_values) end, Data#bba_data.aux_witness)) >= N - F.

%% add X to set Y
add(X, Y) ->
    (1 bsl X) bor Y.

%% is X in set Y?
has(X, Y) ->
    ((1 bsl X) band Y) /= 0.

%% count elements of set
count(2#0) -> 0;
count(2#1) -> 1;
count(2#10) -> 1;
count(2#11) -> 2.

%% get a random value from set
rand_val(2#1) -> 0;
rand_val(2#10) -> 1;
rand_val(2#11) -> hd(hbbft_utils:random_n(1, [0, 1])).

%% get single value from set
val(2#1) -> 0;
val(2#10) -> 1.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

init_test() ->
    N = 5,
    F = 1,
    dealer:start_link(N, F+1, 'SS512'),
    {ok, _PubKey, PrivateKeys} = dealer:deal(),
    gen_server:stop(dealer),
    States = [hbbft_bba:init(Sk, N, F) || Sk <- PrivateKeys],
    StatesWithId = lists:zip(lists:seq(0, length(States) - 1), States),
    %% all valid members should call get_coin
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = input(State, 1),
                            {{J, NewState}, {J, Result}}
                    end, StatesWithId),
    {NewStates, Results} = lists:unzip(Res),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(?MODULE, Results, NewStates, sets:new()),
    %% everyone should converge
    ?assertEqual(N, sets:size(ConvergedResults)),
    ok.

init_with_zeroes_test() ->
    N = 5,
    F = 1,
    dealer:start_link(N, F+1, 'SS512'),
    {ok, _PubKey, PrivateKeys} = dealer:deal(),
    gen_server:stop(dealer),
    States = [hbbft_bba:init(Sk, N, F) || Sk <- PrivateKeys],
    StatesWithId = lists:zip(lists:seq(0, length(States) - 1), States),
    ZeroList = lists:zip([1, 0, 0, 0, 0], StatesWithId),
    %% all valid members should call get_coin
    Res = lists:map(fun({I, {J, State}}) ->
                            {NewState, Result} = input(State, I),
                            {{J, NewState}, {J, Result}}
                    end, ZeroList),
    {NewStates, Results} = lists:unzip(Res),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(?MODULE, Results, NewStates, sets:new()),
    DistinctResults = sets:from_list([BVal || {result, {_, BVal}} <- sets:to_list(ConvergedResults)]),
    ?assertEqual(N, sets:size(ConvergedResults)),
    ?assertEqual([0], sets:to_list(DistinctResults)),
    ok.

init_with_ones_test() ->
    N = 5,
    F = 1,
    dealer:start_link(N, F+1, 'SS512'),
    {ok, _PubKey, PrivateKeys} = dealer:deal(),
    gen_server:stop(dealer),
    States = [hbbft_bba:init(Sk, N, F) || Sk <- PrivateKeys],
    StatesWithId = lists:zip(lists:seq(0, length(States) - 1), States),
    OneList = lists:zip([1, 1, 1, 1, 0], StatesWithId),
    %% all valid members should call get_coin
    Res = lists:map(fun({I, {J, State}}) ->
                            {NewState, Result} = input(State, I),
                            {{J, NewState}, {J, Result}}
                    end, OneList),
    {NewStates, Results} = lists:unzip(Res),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(?MODULE, Results, NewStates, sets:new()),
    DistinctResults = sets:from_list([BVal || {result, {_, BVal}} <- sets:to_list(ConvergedResults)]),
    ?assertEqual(N, sets:size(ConvergedResults)),
    ?assertEqual([1], sets:to_list(DistinctResults)),
    ok.

init_with_mixed_zeros_and_ones_test_() ->
    {timeout, 60, fun() ->
                          N = 10,
                          F = 2,
                          dealer:start_link(N, F+1, 'SS512'),
                          {ok, _PubKey, PrivateKeys} = dealer:deal(),
                          gen_server:stop(dealer),
                          States = [hbbft_bba:init(Sk, N, F) || Sk <- PrivateKeys],
                          StatesWithId = lists:zip(lists:seq(0, length(States) - 1), States),
                          MixedList = lists:zip([1, 1, 1, 0, 1, 0, 0, 0, 0, 0], StatesWithId),
                          %% all valid members should call get_coin
                          Res = lists:map(fun({I, {J, State}}) ->
                                                  {NewState, Result} = input(State, I),
                                                  {{J, NewState}, {J, Result}}
                                          end, MixedList),
                          {NewStates, Results} = lists:unzip(Res),
                          {_, ConvergedResults} = hbbft_test_utils:do_send_outer(?MODULE, Results, NewStates, sets:new()),
                          DistinctResults = sets:from_list([BVal || {result, {_, BVal}} <- sets:to_list(ConvergedResults)]),
                          ?assertEqual(N, sets:size(ConvergedResults)),
                          ?assertEqual(1, sets:size(DistinctResults)),
                          ok
                  end}.

one_dead_test() ->
    N = 5,
    F = 1,
    dealer:start_link(N, F+1, 'SS512'),
    {ok, _PubKey, PrivateKeys} = dealer:deal(),
    gen_server:stop(dealer),
    [S0, S1, _S2, S3, S4] = [hbbft_bba:init(Sk, N, F) || Sk <- PrivateKeys],
    StatesWithId = lists:zip(lists:seq(0, N - 2), [S0, S1, S3, S4]),
    %% all valid members should call get_coin
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = input(State, 1),
                            {{J, NewState}, {J, Result}}
                    end, StatesWithId),
    {NewStates, Results} = lists:unzip(Res),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(?MODULE, Results, NewStates, sets:new()),
    %% everyone but one should converge
    ?assertEqual(N - 1, sets:size(ConvergedResults)),
    ok.

two_dead_test() ->
    N = 5,
    F = 1,
    dealer:start_link(N, F+1, 'SS512'),
    {ok, _PubKey, PrivateKeys} = dealer:deal(),
    gen_server:stop(dealer),
    [S0, S1, _S2, S3, _S4] = [hbbft_bba:init(Sk, N, F) || Sk <- PrivateKeys],
    StatesWithId = lists:zip(lists:seq(0, N - 3), [S0, S1, S3]),
    %% all valid members should call get_coin
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = input(State, 1),
                            {{J, NewState}, {J, Result}}
                    end, StatesWithId),
    {NewStates, Results} = lists:unzip(Res),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(?MODULE, Results, NewStates, sets:new()),
    %% should not converge
    ?assertEqual(0, sets:size(ConvergedResults)),
    ok.
-endif.
