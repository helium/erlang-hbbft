-module(hbbft_handler).

-behavior(relcast).

-export([
         init/1,
         handle_command/2,
         handle_message/3,
         serialize/1,
         deserialize/1,
         restore/2
        ]).

-record(state, {
          hbbft :: hbbft:hbbft(),
          ssk :: tpke_privkey:privkey_serialized()
         }).

init(HBBFTArgs) ->
    DSK = tpke_privkey:deserialize(proplists:get_value(sk, HBBFTArgs)),
    N = proplists:get_value(n, HBBFTArgs),
    F = proplists:get_value(f, HBBFTArgs),
    ID = proplists:get_value(id, HBBFTArgs),
    BatchSize = proplists:get_value(batchsize, HBBFTArgs),
    HBBFT = hbbft:init(DSK, N, F, ID - 1, BatchSize, infinity),
    {ok, #state{hbbft=HBBFT}}.

handle_command({txn, Txn}, State) ->
    case hbbft:input(State#state.hbbft, Txn) of
        {HBBFT, ok} ->
            {reply, ok, [], State#state{hbbft=HBBFT}};
        {HBBFT, full} ->
            {reply, {error, full}, [], State#state{hbbft=HBBFT}};
        {HBBFT, {send, ToSend}} ->
            {reply, ok, fixup_msgs(ToSend), State#state{hbbft=HBBFT}}
    end;
handle_command(Msg, State) ->
    io:format("handle_command, Msg: ~p", [Msg]),
    {reply, ok, [], State}.

handle_message(Msg, Actor, State) ->
    ct:pal("handle_message, Msg: ~p, Actor: ~p~n", [binary_to_term(Msg), Actor]),
    case hbbft:handle_msg(State#state.hbbft, Actor-1, binary_to_term(Msg)) of
        {HBBFT, ok} ->
            {State#state{hbbft=HBBFT}, []};
        {_HBBFT, defer} ->
            defer;
        {HBBFT, {send, ToSend}} ->
            {State#state{hbbft=HBBFT}, fixup_msgs(ToSend)};
        {HBBFT, {result, Res}} ->
            ct:pal("Result: ~p", [Res]),
            {State#state{hbbft=HBBFT}, []}
    end.

serialize(State) ->
    {SerializedHBBFT, SerializedSK} = hbbft:serialize(State#state.hbbft, true),
    term_to_binary(State#state{hbbft=SerializedHBBFT, ssk=SerializedSK}).

deserialize(Binary) ->
    State = binary_to_term(Binary),
    SK = tpke_privkey:deserialize(State#state.ssk),
    HBBFT = hbbft:deserialize(State#state.hbbft, SK),
    #state{hbbft=HBBFT}.

restore(OldState, _NewState) ->
    {ok, OldState}.

%% helper functions

%% hash_block(Block) ->
%%     crypto:hash(sha256, term_to_binary(Block)).
%% 
%% maybe_deserialize_hbbft(HBBFT, SK) ->
%%     case hbbft:is_serialized(HBBFT) of
%%         true -> hbbft:deserialize(HBBFT, SK);
%%         false -> HBBFT
%%     end.
%% 
%% maybe_serialize_HBBFT(HBBFT, ToSerialize) ->
%%     case hbbft:is_serialized(HBBFT) orelse not ToSerialize of
%%         true -> HBBFT;
%%         false -> element(1, hbbft:serialize(HBBFT, false))
%%     end.
fixup_msgs(Msgs) ->
    lists:map(fun({unicast, J, NextMsg}) ->
                      {unicast, J+1, term_to_binary(NextMsg)};
                 ({multicast, NextMsg}) ->
                      {multicast, term_to_binary(NextMsg)}
              end, Msgs).
