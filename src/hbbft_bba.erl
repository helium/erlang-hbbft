-module(hbbft_bba).

-export([init/3, input/2, handle_msg/3, sort_msgs/2, serialize/1, deserialize/2, status/1]).

-record(bba_data, {
          state = init :: init | waiting | done,
          round = 0 :: non_neg_integer(),
          secret_key :: tpke_privkey:privkey(),
          coin :: undefined | hbbft_cc:cc_data(),
          est :: undefined | 0 | 1,
          output :: undefined | 0 | 1,
          f :: non_neg_integer(),
          n :: pos_integer(),
          %% XXX some of these also have the {val, _} keys...
          bval_witness = maps:new() :: #{non_neg_integer() => 0 | 1 | 2 | 3, {val, 0 | 1 | both} => non_neg_integer()},
          aux_witness = maps:new() :: #{non_neg_integer() => 0 | 1 | 2 | 3, {val, 0 | 1 | both} => non_neg_integer()},
          conf_witness = maps:new() :: #{non_neg_integer() => 0 | 1 | 2 | 3},
          terminate_witness = maps:new() :: #{non_neg_integer() => 0 | 1},
          aux_sent = false :: boolean(),
          conf_sent = false :: boolean(),
          coin_sent = false :: boolean(),
          broadcasted = 2#0 :: 0 | 1 | 2 | 3,
          bin_values = 2#00 :: 0 | 1 | 2 | 3
         }).

-record(bba_serialized_data, {
          state = init :: init | waiting | done,
          round = 0 :: non_neg_integer(),
          coin :: undefined | hbbft_cc:cc_serialized_data(),
          est :: undefined | 0 | 1,
          output :: undefined | 0 | 1,
          f :: non_neg_integer(),
          n :: pos_integer(),
          bval_witness = maps:new() :: #{non_neg_integer() => 0 | 1},
          aux_witness = maps:new() :: #{non_neg_integer() => 0 | 1},
          conf_witness = maps:new() :: #{non_neg_integer() => 0 | 1},
          terminate_witness = maps:new() :: #{non_neg_integer() => 0 | 1},
          aux_sent = false :: boolean(),
          conf_sent = false :: boolean(),
          broadcasted = 2#0 :: 0 | 1 | 2 | 3,
          bin_values = 2#00 :: 0 | 1 | 2 | 3
         }).

-type bba_data() :: #bba_data{}.
-type bba_serialized_data() :: #bba_serialized_data{}.

-type bval_msg() :: {bval, non_neg_integer(), 0 | 1}.
-type aux_msg() :: {aux, non_neg_integer(), 0 | 1}.
-type conf_msg() :: {conf, non_neg_integer(), 0 | 1}.
-type term_msg() :: {term, 0 | 1}.
-type coin_msg() :: {{coin, non_neg_integer()}, hbbft_cc:share_msg()}.
-type msgs() :: bval_msg() | aux_msg() | conf_msg() | coin_msg().

-export_type([bba_data/0, bba_serialized_data/0, bval_msg/0, aux_msg/0, coin_msg/0, term_msg/0, msgs/0, conf_msg/0]).

-spec status(bba_data()) -> map().
status(BBAData) ->
    #{state => BBAData#bba_data.state,
      round => BBAData#bba_data.round,
      coin => hbbft_cc:status(BBAData#bba_data.coin),
      aux_sent => BBAData#bba_data.aux_sent,
      conf_sent => BBAData#bba_data.conf_sent,
      coin_sent => BBAData#bba_data.coin_sent,
      output => BBAData#bba_data.output,
      conf_witness => BBAData#bba_data.conf_witness,
      aux_witness => BBAData#bba_data.aux_witness,
      bval_witness => BBAData#bba_data.bval_witness,
      term_witness => BBAData#bba_data.terminate_witness,
      bin_values => BBAData#bba_data.bin_values,
      broadcasted => BBAData#bba_data.broadcasted
     }.

-spec init(tpke_privkey:privkey(), pos_integer(), non_neg_integer()) -> bba_data().
init(SK, N, F) ->
    #bba_data{secret_key=SK, n=N, f=F}.

%% upon receiving input binput , set est0 := binput and proceed as
%% follows in consecutive epochs, with increasing labels r:
%% – multicast BVALr (estr )
%% – bin_values  {}
-spec input(bba_data(), 0 | 1) -> {bba_data(), ok | {send, [hbbft_utils:multicast(bval_msg())]}}.
input(Data = #bba_data{state=init}, BInput) ->
    {Data#bba_data{est = BInput, broadcasted=add(BInput, Data#bba_data.broadcasted)}, {send, [{multicast, {bval, Data#bba_data.round, BInput}}]}};
input(Data = #bba_data{state=done}, _BInput) ->
    {Data, ok}.

-spec handle_msg(bba_data(), non_neg_integer(),
                 coin_msg() |
                 bval_msg() |
                 aux_msg() |
                 conf_msg()) -> {bba_data(), ok} |
                                {bba_data(), defer} |
                                ignore |
                                {bba_data(), {send, [hbbft_utils:multicast(bval_msg() | aux_msg() | conf_msg() | coin_msg())]}} |
                                {bba_data(), {result_and_send, 0 | 1, {send, [hbbft_utils:multicast(term_msg())]}}} |
                                {bba_data(), {result, 0 | 1}}.
handle_msg(#bba_data{state=done}, _J, _BInput) ->
    ignore;
handle_msg(Data = #bba_data{round=R}, J, {bval, R, V}) ->
    bval(Data, J, V);
handle_msg(Data = #bba_data{round=R}, J, {aux, R, V}) ->
    aux(Data, J, V);
handle_msg(Data = #bba_data{round=R}, J, {conf, R, V}) ->
    conf(Data, J, V);
handle_msg(Data = #bba_data{round=R}, _J, {bval, R2, _V}) when R2 > R ->
    %% message is from a future round
    {Data, defer};
handle_msg(Data = #bba_data{round=R}, _J, {aux, R2, _V}) when R2 > R ->
    %% message is from a future round
    {Data, defer};
handle_msg(Data = #bba_data{round=R}, _J, {conf, R2, _V}) when R2 > R ->
    %% message is from a future round
    {Data, defer};
handle_msg(Data = #bba_data{round=R}, _J, {{coin, R2}, _CMsg}) when R2 > R ->
    %% message is from a future round
    {Data, defer};
handle_msg(Data = #bba_data{round=R, coin=Coin}, J, {{coin, R}, CMsg}) when Coin /= undefined ->
    %% dispatch the message to the nested coin protocol
    case hbbft_cc:handle_msg(Data#bba_data.coin, J, CMsg) of
        ignore ->
            ignore;
        {_NewCoin, {result, Result}} ->
            %% ok, we've obtained the common coin
            Flip = Result rem 2,
            check_coin_flip({Data, []}, Flip);
        {NewCoin, ok} ->
            {Data#bba_data{coin=NewCoin}, ok}
    end;
handle_msg(Data = #bba_data{round=R, coin=Coin}, J, Msg = {{coin, R}, _CMsg}) when Coin == undefined ->
    %% we have not called input() yet this round, so we need to manually init the coin
    handle_msg(Data#bba_data{coin=maybe_init_coin(Data)}, J, Msg);
handle_msg(Data, J, {term, B}) when B == 0; B == 1 ->
    %% Another peer has output a value, we can't expect them to send us any more values so we
    %% retain the value they sent us as the virtual value for any subsequent BVAL/AUX/CONF messages
    NewData = add_terminate(J, B, Data),
    %% if we have F+1 Terminate witnesses for a value, we can also terminate with that value
    case maps:get({val, B}, NewData#bba_data.terminate_witness, 0) of
        Count when Count >= Data#bba_data.f + 1 ->
            {NewData#bba_data{state=done}, {result_and_send, B, {send, [{multicast, {term, B}}]}}};
        _ ->
            %% we need to check bval/aux/conf message thresholds in light of the new TERM message
            decide(NewData, [])
    end;
handle_msg(_Data, _J, _Msg) ->
    ignore.

%% – upon receiving BVALr (b) messages from f + 1 nodes, if
%% BVALr (b) has not been sent, multicast BVALr (b)
-spec bval(bba_data(), non_neg_integer(), 0 | 1) -> {bba_data(), {send, [hbbft_utils:multicast(aux_msg() | coin_msg())]}}.
bval(Data=#bba_data{f=F}, Id, V) ->
    %% add to witnesses
    Witness = add_witness(Id, V, Data#bba_data.bval_witness, true),
    WitnessCount = maps:get({val, V}, Witness, 0),

    {NewData, ToSend} = case WitnessCount >= F+1 andalso not has(V, Data#bba_data.broadcasted) of
                            true ->
                                %% add to broadcasted
                                NewData0 = Data#bba_data{bval_witness=Witness,
                                                         broadcasted=add(V, Data#bba_data.broadcasted)},
                                {NewData0, [{multicast, {bval, Data#bba_data.round, V}}]};
                            false ->
                                {Data#bba_data{bval_witness=Witness}, []}
                        end,

    %% - upon receiving BVALr (b) messages from 2 f + 1 nodes,
    %% bin_values_r := bin_valuesr ∪ {b}
    case WitnessCount >= 2*F+1 of
        true ->
            %% add to binvalues
            NewData2 = Data#bba_data{bval_witness=Witness,
                                     bin_values=add(V, NewData#bba_data.bin_values)},
            {NewData3, ToSend2} = case NewData2#bba_data.aux_sent == false of
                                      true ->
                                          %% XXX How many times do we send AUX per round? I think just once
                                          Random = rand_val(NewData2#bba_data.bin_values),
                                          {NewData2#bba_data{aux_sent = true}, ToSend ++ [{multicast, {aux, NewData2#bba_data.round, Random}}]};
                                      false ->
                                          {NewData2, ToSend}
                                  end,
            decide(NewData3, ToSend2);
        false ->
            {NewData, {send, ToSend}}
    end.

-spec aux(bba_data(), non_neg_integer(), 0 | 1) -> {bba_data(), ok | {send, [hbbft_utils:multicast(conf_msg())]}}.
aux(Data, Id, V) ->
    Witness = add_witness(Id, V, Data#bba_data.aux_witness, true),
    NewData = Data#bba_data{aux_witness = Witness},
    decide(NewData, []).

-spec conf(bba_data(), non_neg_integer(), 0 | 1) -> {bba_data(), ok | {send, [hbbft_utils:multicast(coin_msg())]}}.
conf(Data, Id, V) ->
    Witness = maps:put(Id, V, Data#bba_data.conf_witness),
    NewData = Data#bba_data{conf_witness = Witness},
    decide(NewData, []).

sort_msgs(A, B) ->
    msg_order(A) =< msg_order(B).

msg_order({bval, R, _}) -> {R, 0};
msg_order({aux, R, _}) -> {R, 1};
msg_order({conf, R, _}) -> {R, 2};
msg_order({{coin, R}, _}) -> {R, 3};
msg_order(_) -> {infinity, 4}.

-spec serialize(bba_data()) -> bba_serialized_data().
serialize(#bba_data{state=State,
                    round=Round,
                    coin=Coin,
                    est=Est,
                    output=Output,
                    f=F,
                    n=N,
                    bval_witness=Witness,
                    aux_witness=AuxWitness,
                    conf_witness=ConfWitness,
                    terminate_witness=TermWitness,
                    aux_sent=AuxSent,
                    conf_sent=ConfSent,
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
                         bval_witness=Witness,
                         aux_witness=AuxWitness,
                         conf_witness=ConfWitness,
                         terminate_witness=TermWitness,
                         aux_sent=AuxSent,
                         conf_sent=ConfSent,
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
                                 bval_witness=Witness,
                                 aux_witness=AuxWitness,
                                 conf_witness=ConfWitness,
                                 terminate_witness=TermWitness,
                                 aux_sent=AuxSent,
                                 conf_sent=ConfSent,
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
              bval_witness=Witness,
              aux_witness=AuxWitness,
              conf_witness=ConfWitness,
              terminate_witness=TermWitness,
              aux_sent=AuxSent,
              conf_sent=ConfSent,
              broadcasted=Broadcasted,
              bin_values=BinValues}.


%% helper functions


decide(Data=#bba_data{n=N, f=F}, ToSend0) ->
    %% check if we have n-f aux messages
    case threshold(N, F, Data, aux) of
        true ->
            case schedule(Data#bba_data.round) of
                coin ->
                    %% only send conf after n-f aux messages
                    {NewData, ToSend} = case Data#bba_data.conf_sent of
                                              false ->
                                                  {Data#bba_data{conf_sent=true}, ToSend0 ++ [{multicast, {conf, Data#bba_data.round, Data#bba_data.bin_values}}]};
                                              true ->
                                                  %% conf was already sent
                                                  {Data, ToSend0}
                                          end,
                    %% check if we have n-f conf messages
                    case threshold(N, F, NewData, conf) andalso not NewData#bba_data.coin_sent of
                        true ->
                            %% instantiate the common coin
                            %% TODO need more entropy for the SID
                            %% We have enough AUX and CONF messages to reveal our share of the coin
                            {CoinData, {send, CoinSend}} = hbbft_cc:get_coin(maybe_init_coin(NewData)),
                            {NewData#bba_data{coin=CoinData, coin_sent=true}, {send, ToSend ++ hbbft_utils:wrap({coin, NewData#bba_data.round}, CoinSend)}};
                        _ ->
                            {NewData, {send, ToSend}}
                    end;
                FixedValue ->
                    check_coin_flip({Data, ToSend0}, FixedValue)
            end;
        false ->
            {Data, {send, ToSend0}}
    end.

-spec threshold(pos_integer(), non_neg_integer(), bba_data(), aux | conf) -> boolean().
threshold(N, F, Data, Msg) ->
    case Msg of
        aux -> check(N, F, Data#bba_data.bin_values, Data#bba_data.aux_witness, Data#bba_data.terminate_witness);
        conf -> check(N, F, Data#bba_data.bin_values, Data#bba_data.conf_witness, Data#bba_data.terminate_witness, fun subset/2)
    end.

-spec check(pos_integer(), non_neg_integer(), 0 | 1 | 2 | 3, #{non_neg_integer() => 0 | 1}, #{}) -> boolean().
check(N, F, ToCheck, Witness, Terms) ->
    case ToCheck of
        0 ->
            false;
        1 ->
            maps:get({val, 0}, Witness, 0) + maps:get({val, 0}, Terms, 0) >= N - F;
        2 ->
            maps:get({val, 1}, Witness, 0) + maps:get({val, 1}, Terms, 0) >= N - F;
        3 ->
            %% both
            Both = maps:get({val, both}, Witness, 0),
            Zeros = maps:get({val, 0}, Witness, 0) + maps:get({val, 0}, Terms, 0),
            Ones = maps:get({val, 1}, Witness, 0) + maps:get({val, 1}, Terms, 0),
            Both + (Zeros - Both) + (Ones - Both) >= N - F
    end.

-spec check(pos_integer(), non_neg_integer(), 0 | 1 | 2 | 3, #{non_neg_integer() => 0 | 1}, #{}, fun((0|1|2|3, 0|1|2|3) -> boolean())) -> boolean().
check(N, F, ToCheck, Map, Terms, Fun) ->
    maps:fold(fun({val, _}, _, Acc) ->
                      %% don't count memoized fields
                      Acc;
                 (_, V, Acc) ->
                      case Fun(V, ToCheck) of
                          true ->
                              Acc + 1;
                          false -> Acc
                      end
              end, 0, maps:merge(Map, Terms)) >= N - F.

maybe_init_coin(Data) ->
    case Data#bba_data.coin of
        undefined ->
            hbbft_cc:init(Data#bba_data.secret_key, term_to_binary({Data#bba_data.round}), Data#bba_data.n, Data#bba_data.f);
        C -> C
    end.

%% add X to set Y
add(X, Y) ->
    (1 bsl X) bor Y.

%% is X in set Y?
has(X, Y) ->
    ((1 bsl X) band Y) /= 0.

%% is X a subset of Y?
subset(X, Y) ->
    (X band Y) == X.

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

add_witness(Id, Value, Witness, AllowUnion) ->
    Old = maps:get(Id, Witness, 0),
    New = add(Value, Old),
    case Old /= New of
        true when New == 3, AllowUnion == false ->
            %% not allowed to update or merge the value
            Witness;
        true when Old /= 0, AllowUnion == false ->
            %% now allowed to update a value
            Witness;
        true when New == 3 ->
            OldCount = maps:get({val, Value}, Witness, 0),
            OldBothCount = maps:get({val, both}, Witness, 0),
            maps:merge(Witness, #{{val, Value} => OldCount + 1, Id => New, {val, both} => OldBothCount + 1});
        true  ->
            OldCount = maps:get({val, Value}, Witness, 0),
            maps:merge(Witness, #{{val, Value} => OldCount + 1, Id => New});
        false ->
            Witness
    end.

remove_witness(ID, Witness) ->
    Old = maps:get(ID, Witness, 0),
    case Old of
        0 ->
            Witness;
        3 ->
            OldCount0 = maps:get({val, 0}, Witness, 1),
            OldCount1 = maps:get({val, 1}, Witness, 1),
            OldBothCount = maps:get({val, both}, Witness, 1),
            maps:merge(maps:remove(ID, Witness), #{{val, 0} => OldCount0 - 1, {val, 1} => OldCount1 - 1, {val, both} => OldBothCount - 1});
        Val ->
            OldCount = maps:get({val, val(Val)}, Witness, 1),
            maps:merge(maps:remove(ID, Witness), #{{val, val(Val)} => OldCount - 1})
    end.

add_terminate(Id, Value, Data) ->
    TerminateWitness = add_witness(Id, Value, Data#bba_data.terminate_witness, false),
    %% XXX can we naively delete bval/aux/conf witness values here? what if the terminate witness
    %% value isn't the same as the aux witness value?
    BValWitness = remove_witness(Id, Data#bba_data.bval_witness),
    AuxWitness = remove_witness(Id, Data#bba_data.aux_witness),
    ConfWitness = remove_witness(Id, Data#bba_data.conf_witness),
    Data#bba_data{bval_witness=BValWitness, aux_witness=AuxWitness, conf_witness=ConfWitness, terminate_witness=TerminateWitness}.

schedule(0) -> 1;
schedule(1) -> 1;
schedule(2) -> 0;
schedule(3) -> 0;
schedule(4) -> coin;
schedule(N) ->
    case (N - 5) rem 3 of
        0 -> 1;
        1 -> 0;
        2 -> coin
    end.

check_coin_flip({Data, ToSend}, Flip) ->
    case count(Data#bba_data.bin_values) == 1 of
        true ->
            %% if vals = {b}, then
            B = val(Data#bba_data.bin_values),
            Output = case Flip == B of
                         true ->
                             %% if (b = s%2) then output b
                             B;
                         false ->
                             undefined
                     end,
            case B == Flip andalso Data#bba_data.output == B of
                true ->
                    %% we are done
                    NewData = Data#bba_data{state=done},
                    {NewData, {result_and_send, B, {send, ToSend ++ [{multicast, {term, B}}]}} };
                false ->
                    %% increment round and continue
                    NewData = init(Data#bba_data.secret_key, Data#bba_data.n, Data#bba_data.f),
                    {NewData2, {send, NewToSend}} = input(NewData#bba_data{round=Data#bba_data.round + 1, output=Output, terminate_witness=Data#bba_data.terminate_witness}, B),
                    {NewData2, {send, ToSend ++ NewToSend}}
            end;
        false ->
            %% else estr+1 := s%2
            B = Flip,
            NewData = init(Data#bba_data.secret_key, Data#bba_data.n, Data#bba_data.f),
            {NewData2, {send, NewToSend}} = input(NewData#bba_data{round=Data#bba_data.round + 1, terminate_witness=Data#bba_data.terminate_witness}, B),
            {NewData2, {send, ToSend ++ NewToSend}}
    end.
