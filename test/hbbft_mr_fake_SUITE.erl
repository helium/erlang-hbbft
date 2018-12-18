-module(hbbft_mr_fake_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-include_lib("relcast/include/fakecast.hrl").

-export([all/0, init_per_testcase/2, end_per_testcase/2]).
-export([
         multi_round_fakecast_test/1
        ]).

all() ->
    [
     multi_round_fakecast_test
    ].

init_per_testcase(_, Config) ->
    N = 4,
    F = 1,
    Module = hbbft,
    BatchSize = 10,
    {ok, Dealer} = dealer:new(N, F+1, 'SS512'),
    {ok, {PubKey, PrivateKeys}} = dealer:deal(Dealer),
    [{n, N}, {f, F}, {batchsize, BatchSize}, {module, Module}, {pubkey, PubKey}, {privatekeys, PrivateKeys} | Config].

end_per_testcase(_, _Config) ->
    ok.


-record(state,
        {
         round = 0 :: non_neg_integer(),
         node_count :: integer(),
         all_msgs :: [term()],
         to_deliver :: [term()],
         txns = [] :: [term()],
         results = #{} :: #{Round::integer() => boolean()}
        }).

%% clause for input

time_mr(Time, Nodes, ModelState) ->
    %% ideally we'd only run this once per tick?
    case Time /= 0 andalso Time rem 1000 of
        0 ->
            Nodes1 =
                maps:fold(fun(ID, _Node, Nds) ->
                                  #{ID := #node{state = State} = Node} = Nds,
                                  {State1, Actions} = hbbft:start_on_demand(State),
                                  Nds1 = Nds#{ID => Node#node{state = State1}},
                                  fakecast:trace("XXXX actions ~p ~p", [ID, Actions]),
                                  case Actions of
                                      {send, Messages} ->
                                          fakecast:send_messages(ID, Nds1,
                                                                 Messages);
                                      _ ->
                                          Nds1
                                  end
                          end,
                          Nodes,
                          Nodes),
            {Nodes1, ModelState};
        _ ->
            {Nodes, ModelState}
    end.

mr(_Message, _From, _To, _State, NewState, Nothing,
   #state{to_deliver = Deliver} = ModelState) when Nothing == [] orelse
                                                   Nothing == ok orelse
                                                   Nothing == ignored ->
    case Deliver of
        [] ->
            {actions, [], ModelState};
        [Msg|T] ->
            case rand:uniform(5) of
                %% do this so that txns end up on more nodes but
                %% eventually trend to []
                1 ->
                    {NewState1, Actions} = hbbft:input(NewState, Msg),
                    {actions, [{alter_state, NewState1},
                               {alter_actions, Actions}],
                     ModelState#state{to_deliver = Deliver}};
                2 ->
                    {NewState1, Actions} = hbbft:input(NewState, Msg),
                    {actions, [{alter_state, NewState1},
                               {alter_actions, Actions}],
                     ModelState#state{to_deliver = T}};
                _ ->
                    {actions, [], ModelState}
            end
    end;
mr(_Message, _From, _To, _State, NewState,
   {result, {transactions, _Stamps, Txns}},
   #state{results = Results,
          all_msgs = Msgs,
          txns = StateTxns} = ModelState) ->
    %% !!!!!!  note that this is fragile and may break if the record changes
    Round = element(7, NewState),

    %% finalize the round for this node
    NewNewState = hbbft:finalize_round(NewState, Txns),
    {NewNewNewState, Actions} = hbbft:next_round(NewNewState),
    fakecast:trace("buffer remaining ~p", [length(element(8, NewNewNewState))]),

    %% check if all messages have been put into the queue, and if all
    %% messages have appeared as transactions.
    case Results of
        #{Round := CanonTxns} ->
            %% already seen this round, continue
            case CanonTxns of
                Txns ->
                    {actions,
                     [{alter_state, NewNewNewState},
                      {alter_actions, Actions}],
                     ModelState};
                _ ->
                    {fail, {mismatched_txns, CanonTxns, Txns}}
            end;
        _ ->
            %% first time seeing this round's results (not BFT-safe,
            %% but we don't act in a byzantine manner
            StateTxns1 = lists:sort(lists:append(Txns, StateTxns)),
            Msgs1 = Msgs -- Txns,
            fakecast:trace("first result msgs ~p -> ~p",
                           [length(Msgs), length(Msgs1)]),
            case Msgs1 of
                [] -> success;
                _ ->
                    {actions,
                     [{alter_state, NewNewNewState},
                      {alter_actions, Actions}],
                     ModelState#state{
                       results = Results#{Round => Txns},
                       txns = StateTxns1,
                       all_msgs = Msgs1}}
            end
    end;
mr(_Message, _From, _To, _NodeState, _NewState, _Actions, ModelState) ->
    {actions, [], ModelState}.

multi_round_fakecast_test(Config) ->
    N = 4, % proplists:get_value(n, Config),
    F = 1, % proplists:get_value(f, Config),
    BatchSize = proplists:get_value(batchsize, Config),
    Module = proplists:get_value(module, Config),
    PrivateKeys0 = proplists:get_value(privatekeys, Config),
    {PrivateKeys, _} = lists:split(N, PrivateKeys0),

    Msgs = [ crypto:strong_rand_bytes(128) || _ <- lists:seq(1, 200)],
    {InitMsgs, LaterMsgs} = lists:split(50, Msgs),
    Init = fun() ->
                   {ok,
                    #fc_conf{
                       test_mod = Module,
                       nodes = lists:seq(1, N),
                       configs = [[Sk, N, F, ID, BatchSize, infinity]
                                  || {ID, Sk} <- lists:zip(lists:seq(0, N - 1), PrivateKeys)],
                       max_time = 20000
                      },
                    #state{node_count = N,
                           all_msgs = Msgs,
                           to_deliver = LaterMsgs}
                   }
           end,
    %% send each message to a random subset of the HBBFT actors
    Input =
        fun() ->
                lists:foldl(fun(ID, Acc) ->
                                    Size = max(length(InitMsgs), BatchSize + (rand:uniform(length(InitMsgs)))),
                                    Subset = random_n(Size, InitMsgs),
                                    lists:append([{ID, Msg} || Msg <- Subset], Acc)
                            end, [], lists:seq(0, N - 1))
        end,
    %% start it on runnin'
    ok = fakecast:start_test(Init, fun mr/7,
                             {1545,90841,95111}, %os:timestamp(),
                             Input,
                             #{time_model => fun time_mr/3}).

%% helper functions

%% enumerate(List) ->
%%     lists:zip(lists:seq(0, length(List) - 1), List).

random_n(N, List) ->
    lists:sublist(shuffle(List), N).

shuffle(List) ->
    [X || {_,X} <- lists:sort([{rand:uniform(), N} || N <- List])].
