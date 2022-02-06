-module(hbbft_handler).

-behavior(relcast).

-export([
         init/1,
         handle_command/2,
         handle_message/3,
         callback_message/3,
         serialize/1,
         deserialize/1,
         restore/2
        ]).

-record(state, {
          hbbft :: hbbft:hbbft(),
          sk :: tc_key_share:tc_key_share(),
          ssk :: binary()
         }).

init(HBBFTArgs) ->
    SK = tc_key_share:deserialize(proplists:get_value(sk, HBBFTArgs)),
    N = proplists:get_value(n, HBBFTArgs),
    F = proplists:get_value(f, HBBFTArgs),
    ID = proplists:get_value(id, HBBFTArgs),
    BatchSize = proplists:get_value(batchsize, HBBFTArgs),
    HBBFT = hbbft:init(SK, N, F, ID - 1, BatchSize, infinity),
    {ok, #state{hbbft=HBBFT, sk=SK}}.

handle_command({txn, Txn}, State) ->
    case hbbft:input(State#state.hbbft, Txn) of
        {HBBFT, {result, _}} ->
            {reply, ok, [], State#state{hbbft=HBBFT}};
        {_HBBFT, full} ->
            {reply, {error, full}, ignore};
        {HBBFT, {result_and_send, _, {send, ToSend}}} ->
            {reply, ok, fixup_msgs(ToSend), State#state{hbbft=HBBFT}}
    end;
handle_command({finalize_round, Txns, TempBlock}, State) ->
    {HBBFT, {send, ToSend}} = hbbft:finalize_round(State#state.hbbft, Txns, TempBlock),
    {reply, ok, fixup_msgs(ToSend), State#state{hbbft=HBBFT}};
handle_command(next_round, State) ->
    {HBBFT, _} = hbbft:next_round(State#state.hbbft),
    {reply, ok, [new_epoch], State#state{hbbft=HBBFT}};
handle_command(start_on_demand, State) ->
    case hbbft:start_on_demand(State#state.hbbft) of
        {HBBFT, already_started} ->
            {reply, {error, already_started}, [], State#state{hbbft=HBBFT}};
        {HBBFT, {send, ToSend}} ->
            %ct:pal("started hbbft on demand", []),
            {reply, ok, fixup_msgs(ToSend), State#state{hbbft=HBBFT}}
    end;
handle_command({status, From}, State) ->
    Status = hbbft:status(State#state.hbbft),
    gen_server:reply(From, Status),
    {reply, ok, ignore};
handle_command(_Msg, _State) ->
    %ct:pal("unhandled handle_command, Msg: ~p", [_Msg]),
    {reply, ok, ignore}.

handle_message(Msg, Actor, State) ->
    %ct:pal("Msg ~p", [binary_to_term(Msg)]),
    case hbbft:handle_msg(State#state.hbbft, Actor-1, binary_to_term(Msg)) of
        {HBBFT, ok} ->
            {State#state{hbbft=HBBFT}, []};
        {_HBBFT, defer} ->
            defer;
        ignore ->
            ignore;
        {HBBFT, {send, ToSend}} ->
            {State#state{hbbft=HBBFT}, fixup_msgs(ToSend)};
        {HBBFT, {result, {transactions, _, Txns}}} ->
            self() ! {transactions, Txns},
            {State#state{hbbft=HBBFT}, []};
        {HBBFT, {result, {signature, Sig}}} ->
            self() ! {signature, Sig},
            {State#state{hbbft=HBBFT}, []}
    end.

callback_message(_, _, _) ->
    none.

serialize(State) ->
    {SerializedHBBFT, SerializedSK} = hbbft:serialize(State#state.hbbft, true),
    term_to_binary(State#state{hbbft=SerializedHBBFT, ssk=SerializedSK}).

deserialize(Binary) ->
    State = binary_to_term(Binary),
    SK = tc_key_share:deserialize(State#state.ssk),
    HBBFT = hbbft:deserialize(State#state.hbbft, SK),
    #state{hbbft=HBBFT}.

restore(OldState, _NewState) ->
    {ok, OldState}.

%% helper functions
fixup_msgs(Msgs) ->
    lists:map(fun({unicast, J, NextMsg}) ->
                      {unicast, J+1, term_to_binary(NextMsg)};
                 ({multicast, NextMsg}) ->
                      {multicast, term_to_binary(NextMsg)}
              end, Msgs).
