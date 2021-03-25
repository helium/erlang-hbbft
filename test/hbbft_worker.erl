-module(hbbft_worker).

-behaviour(gen_server).

-export([start_link/6, submit_transaction/2, start_on_demand/1, get_blocks/1]).
-export([verify_chain/2, block_transactions/1, status/1, set_filter/2]).
-export([bba_filter/1]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-record(block, {
          prev_hash :: binary(),
          transactions :: [binary()],
          signature :: binary()
         }).

-record(state, {
          n :: non_neg_integer(),
          id :: non_neg_integer(),
          hbbft :: hbbft:hbbft_data(),
          blocks :: [#block{}],
          tempblock :: undefined | #block{},
          sk :: tc_key_share:tc_key_share(),
          ssk :: binary(),
          to_serialize = false :: boolean(),
          filter = fun(_ID, _Msg) -> true end :: fun((any()) -> boolean())
         }).

start_link(N, F, ID, SK, BatchSize, ToSerialize) ->
    gen_server:start_link({global, name(ID)}, ?MODULE, [N, F, ID, SK, BatchSize, ToSerialize], []).

submit_transaction(Msg, Pid) ->
    gen_server:call(Pid, {submit_txn, Msg}, infinity).

start_on_demand(Pid) ->
    gen_server:call(Pid, start_on_demand, infinity).

get_blocks(Pid) ->
    gen_server:call(Pid, get_blocks, infinity).

status(Pid) ->
    gen_server:call(Pid, status, infinity).

set_filter(Fun, Pid) when is_function(Fun) ->
    gen_server:call(Pid, {set_filter, Fun}, infinity).

bba_filter(ID) ->
    fun(I, {{acs,_},{{bba, I}, _}}=Msg) when I == ID ->
            ct:log("~p filtering ~p~n", [node(), Msg]),
            false;
       (_, _) -> true
    end.

verify_chain([], _) ->
    true;
verify_chain([G], PubKey) ->
    ct:log("verifying genesis block~n"),
    %% genesis block has no prev hash
    case G#block.prev_hash == <<>> of
        true ->
            %% genesis block should have a valid signature
            %Signature = signature:deserialize(G#block.signature),
            tc_key_share:verify(PubKey, G#block.signature, term_to_binary(G#block{signature= <<>>}));
        false ->
            ct:log("no genesis block~n"),
            false
    end;
verify_chain(Chain, PubKey) ->
    ct:log("Chain verification depth ~p~n", [length(Chain)]),
    case verify_block_fit(Chain, PubKey) of
        true -> verify_chain(tl(Chain), PubKey);
        false ->
            ct:log("bad signature~n"),
            false
    end.

verify_block_fit([B], _) when B#block.prev_hash == <<>> -> true;
verify_block_fit([A, B | _], PubKey) ->
    %% A should have the the prev_hash of B
    case A#block.prev_hash == hash_block(B) of
        true ->
            %% A should have a valid signature
            %Signature = signature:deserialize(A#block.signature),
            case tc_key_share:verify(PubKey, A#block.signature, term_to_binary(A#block{signature= <<>>})) of
                true ->
                    true;
                false ->
                    ct:log("bad signature~n"),
                    false
            end;
        false ->
            ct:log("parent hash mismatch ~p ~p~n", [A#block.prev_hash, hash_block(B)]),
            false
    end.

block_transactions(Block) ->
    Block#block.transactions.

init([N, F, ID, SK, BatchSize, ToSerialize]) ->
    %% deserialize the secret key once
    DSK = tc_key_share:deserialize(SK),
    %% init hbbft
    HBBFT = hbbft:init(DSK, N, F, ID, BatchSize, infinity),
    %% store the serialized state and serialized SK
    {ok, #state{hbbft=HBBFT, blocks=[], id=ID, n=N, sk=DSK, ssk=SK, to_serialize=ToSerialize}}.

handle_call(start_on_demand, _From, State = #state{hbbft=HBBFT, sk=SK}) ->
    NewState = dispatch(hbbft:start_on_demand(maybe_deserialize_hbbft(HBBFT, SK)), State),
    {reply, ok, NewState};
handle_call({submit_txn, Txn}, _From, State = #state{hbbft=HBBFT, sk=SK}) ->
    NewState = dispatch(hbbft:input(maybe_deserialize_hbbft(HBBFT, SK), Txn), State),
    {reply, ok, NewState};
handle_call(get_blocks, _From, State) ->
    {reply, {ok, State#state.blocks}, State};
handle_call(status, _From, State  = #state{hbbft=HBBFT, sk=SK}) ->
    {reply, hbbft:status(maybe_deserialize_hbbft(HBBFT, SK)), State};
handle_call({set_filter, Fun}, _From, State) ->
    {reply, ok, State#state{filter=Fun}};
handle_call(Msg, _From, State) ->
    ct:log("unhandled msg ~p~n", [Msg]),
    {reply, ok, State}.

handle_cast({hbbft, PeerID, Msg}, State = #state{hbbft=HBBFT, sk=SK, filter=Filter}) ->
    case Filter(PeerID, Msg) of
        true ->
            case hbbft:handle_msg(maybe_deserialize_hbbft(HBBFT, SK), PeerID, Msg) of
                {NewHBBFT, defer} ->
                    gen_server:cast(self(), {hbbft, PeerID, Msg}),
                    {noreply, State#state{hbbft=maybe_serialize_HBBFT(NewHBBFT, State#state.to_serialize)}};
                Result ->
                    NewState = dispatch(Result, State),
                    {noreply, NewState}
            end;
        false ->
            {noreply, State}
    end;
handle_cast({block, NewBlock}, State=#state{sk=SK, hbbft=HBBFT}) ->
    case lists:member(NewBlock, State#state.blocks) of
        false ->
            ct:log("XXXXXXXX~n"),
            %% a new block, check if it fits on our chain
            case verify_block_fit([NewBlock|State#state.blocks], SK) of
                true ->
                    %% advance to the next round
                    ct:log("~p skipping to next round~n", [self()]),
                    %% remove any transactions we have from our queue (drop the signature messages, they're not needed)
                    {NewHBBFT, _} = hbbft:finalize_round(maybe_deserialize_hbbft(HBBFT, SK), NewBlock#block.transactions, term_to_binary(NewBlock)),
                    NewState = dispatch(hbbft:next_round(maybe_deserialize_hbbft(NewHBBFT, SK)), State#state{blocks=[NewBlock | State#state.blocks]}),
                    {noreply, NewState#state{tempblock=undefined}};
                false ->
                    ct:log("invalid block proposed~n"),
                    {noreply, State}
            end;
        true ->
            {noreply, State}
    end;
handle_cast(Msg, State) ->
    ct:log("unhandled msg ~p~n", [Msg]),
    {noreply, State}.

handle_info(Msg, State) ->
    ct:log("unhandled msg ~p~n", [Msg]),
    {noreply, State}.

dispatch({NewHBBFT, {send, ToSend}}, State) ->
    do_send(ToSend, State),
    State#state{hbbft=maybe_serialize_HBBFT(NewHBBFT, State#state.to_serialize)};
dispatch({NewHBBFT, {result, {transactions, _, Txns}}}, State) ->
    ct:pal("got transactions ~p", [Txns]),
    NewBlock = case State#state.blocks of
                   [] ->
                       %% genesis block
                       #block{prev_hash= <<>>, transactions=Txns, signature= <<>>};
                   [PrevBlock|_Blocks] ->
                       #block{prev_hash=hash_block(PrevBlock), transactions=Txns, signature= <<>>}
               end,
    %% tell the badger to finish the round
    dispatch(hbbft:finalize_round(maybe_deserialize_hbbft(NewHBBFT, State#state.sk), Txns, term_to_binary(NewBlock)), State#state{tempblock=NewBlock});
dispatch({NewHBBFT, {result, {signature, Sig}}}, State = #state{tempblock=NewBlock0}) ->
    NewBlock = NewBlock0#block{signature=Sig},
    [ gen_server:cast({global, name(Dest)}, {block, NewBlock}) || Dest <- lists:seq(0, State#state.n - 1)],
    dispatch(hbbft:next_round(maybe_deserialize_hbbft(NewHBBFT, State#state.sk)), State#state{blocks=[NewBlock|State#state.blocks], tempblock=undefined});
dispatch({NewHBBFT, ok}, State) ->
    State#state{hbbft=maybe_serialize_HBBFT(NewHBBFT, State#state.to_serialize)};
dispatch({NewHBBFT, Other}, State) ->
    ct:log("~p UNHANDLED ~p~n", [self(), Other]),
    State#state{hbbft=maybe_serialize_HBBFT(NewHBBFT, State#state.to_serialize)};
dispatch(Other, State) ->
    ct:log("~p UNHANDLED2 ~p~n", [self(), Other]),
    State.

do_send([], _) ->
    ok;
do_send([{unicast, Dest, Msg}|T], State) ->
    ct:log("~p unicasting ~p to ~p~n", [State#state.id, Msg, global:whereis_name(name(Dest))]),
    gen_server:cast({global, name(Dest)}, {hbbft, State#state.id, Msg}),
    do_send(T, State);
do_send([{multicast, Msg}|T], State) ->
    ct:log("~p multicasting ~p to ~p~n", [State#state.id, Msg, [global:whereis_name(name(Dest)) || Dest <- lists:seq(0, State#state.n - 1)]]),
    [ gen_server:cast({global, name(Dest)}, {hbbft, State#state.id, Msg}) || Dest <- lists:seq(0, State#state.n - 1)],
    do_send(T, State).


%% helper functions
name(N) ->
    list_to_atom(lists:flatten(["hbbft_worker_", integer_to_list(N)])).

hash_block(Block) ->
    crypto:hash(sha256, term_to_binary(Block)).

maybe_deserialize_hbbft(HBBFT, SK) ->
    case hbbft:is_serialized(HBBFT) of
        true -> hbbft:deserialize(HBBFT, SK);
        false -> HBBFT
    end.

maybe_serialize_HBBFT(HBBFT, ToSerialize) ->
    case hbbft:is_serialized(HBBFT) orelse not ToSerialize of
        true -> HBBFT;
        false -> element(1, hbbft:serialize(HBBFT, false))
    end.
