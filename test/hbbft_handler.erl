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
          hbbft :: hbbft:hbbft()
         }).

init(HBBFTArgs) ->
    DSK = tpke_privkey:deserialize(proplists:get_value(sk, HBBFTArgs)),
    N = proplists:get_value(n, HBBFTArgs),
    F = proplists:get_value(f, HBBFTArgs),
    ID = proplists:get_value(id, HBBFTArgs),
    BatchSize = proplists:get_value(batchsize, HBBFTArgs),

    HBBFT = hbbft:init(DSK, N, F, ID, BatchSize, infinity),

    {ok, #state{hbbft=HBBFT}}.

handle_command(Msg, State) ->
    io:format("handle_command, Msg: ~p", [Msg]),
    {reply, ok, [], State}.

handle_message(Msg, Actor, State) ->
    ct:pal("handle_message, Msg: ~p, Actor: ~p~n", [Msg, Actor]),
    {State, []}.

serialize(State) ->
    ct:pal("Serialize: ~p~n", [State]),
    term_to_binary(State).

deserialize(Binary) ->
    ct:pal("Deserialize: ~p~n", [Binary]),
    binary_to_term(Binary).

restore(OldState, NewState) ->
    ct:pal("OldState: ~p, NewState: ~p~n", [OldState, NewState]),
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
