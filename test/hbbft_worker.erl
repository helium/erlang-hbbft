-module(hbbft_worker).

-behaviour(gen_server).

-export([start_link/4, submit_transaction/2, get_blocks/1]).
-export([verify_chain/2, block_transactions/1]).

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
          sk :: tpke_privkey:private_key()
         }).

start_link(N, F, ID, SK) ->
    gen_server:start_link({global, name(ID)}, ?MODULE, [N, F, ID, tpke_privkey:deserialize(SK)], []).
    %gen_server:start_link({global, name(ID)}, ?MODULE, [N, F, ID, SK], []).

submit_transaction(Msg, Pid) ->
    gen_server:call(Pid, {submit_txn, Msg}, infinity).

get_blocks(Pid) ->
    gen_server:call(Pid, get_blocks, infinity).

verify_chain([], _) ->
    true;
verify_chain([G], PubKey) ->
    io:format("verifying genesis block~n"),
    %% genesis block has no prev hash
    case G#block.prev_hash == <<>> of
        true ->
            %% genesis block should have a valid signature
            HM = tpke_pubkey:hash_message(PubKey, term_to_binary(G#block{signature= <<>>})),
            Signature = tpke_pubkey:deserialize_element(PubKey, G#block.signature),
            tpke_pubkey:verify_signature(PubKey, Signature, HM);
        false ->
            io:format("no genesis block~n"),
            false
    end;
verify_chain([A, B|_]=Chain, PubKey) ->
    io:format("Chain verification depth ~p~n", [length(Chain)]),
    %% A should have the the prev_hash of B
    case A#block.prev_hash == hash_block(B) of
        true ->
            %% A should have a valid signature
            HM = tpke_pubkey:hash_message(PubKey, term_to_binary(A#block{signature= <<>>})),
            Signature = tpke_pubkey:deserialize_element(PubKey, A#block.signature),
            case tpke_pubkey:verify_signature(PubKey, Signature, HM) of
                true ->
                    verify_chain(tl(Chain), PubKey);
                false ->
                    io:format("bad signature~n"),
                    false
            end;
        false ->
            io:format("parent hash mismatch ~p ~p~n", [A#block.prev_hash, hash_block(B)]),
            false
    end.

block_transactions(Block) ->
    Block#block.transactions.

init([N, F, ID, SK]) ->
    HBBFT = hbbft:init(SK, N, F, ID, 20),
    {ok, #state{hbbft=HBBFT, blocks=[], id=ID, n=N, sk=SK}}.

handle_call({submit_txn, Txn}, _From, State = #state{hbbft=HBBFT}) ->
    NewState = dispatch(hbbft:input(HBBFT, Txn), State),
    {reply, ok, NewState};
handle_call(get_blocks, _From, State) ->
    {reply, {ok, State#state.blocks}, State};
handle_call(Msg, _From, State) ->
    io:format("unhandled msg ~p~n", [Msg]),
    {reply, ok, State}.

handle_cast({hbbft, PeerID, Msg}, State = #state{hbbft=HBBFT}) ->
    NewState = dispatch(hbbft:handle_msg(HBBFT, PeerID, Msg), State),
    {noreply, NewState};
handle_cast({block, NewBlock}, State) ->
    case lists:member(NewBlock, State#state.blocks) of
        false ->
            io:format("XXXXXXXX~n"),
            %% a new block, check if it fits on our chain
            case verify_chain([NewBlock|State#state.blocks], tpke_privkey:public_key(State#state.sk)) of
                true ->
                    %% advance to the next round
                    io:format("~p skipping to next round~n", [self()]),
                    %% remove any transactions we have from our queue (drop the signature messages, they're not needed)
                    {NewHBBFT, _} = hbbft:finalize_round(State#state.hbbft, NewBlock#block.transactions, term_to_binary(NewBlock)),
                    NewState = dispatch(hbbft:next_round(NewHBBFT), State#state{blocks=[NewBlock|State#state.blocks]}),
                    {noreply, NewState#state{tempblock=undefined}};
                false ->
                    io:format("invalid block proposed~n"),
                    {noreply, State}
            end;
        true ->
            {noreply, State}
    end;
handle_cast(Msg, State) ->
    io:format("unhandled msg ~p~n", [Msg]),
    {noreply, State}.

handle_info(Msg, State) ->
    io:format("unhandled msg ~p~n", [Msg]),
    {noreply, State}.

dispatch({NewHBBFT, {send, ToSend}}, State) ->
    do_send(ToSend, State),
    State#state{hbbft=NewHBBFT};
dispatch({NewHBBFT, {result, {transactions, Txns}}}, State) ->
    NewBlock = case State#state.blocks of
                   [] ->
                       %% genesis block
                       #block{prev_hash= <<>>, transactions=Txns, signature= <<>>};
                   [PrevBlock|_Blocks] ->
                       #block{prev_hash=hash_block(PrevBlock), transactions=Txns, signature= <<>>}
               end,
    %% tell the badger to finish the round
    dispatch(hbbft:finalize_round(NewHBBFT, Txns, term_to_binary(NewBlock)), State#state{tempblock=NewBlock});
dispatch({NewHBBFT, {result, {signature, Sig}}}, State = #state{tempblock=NewBlock0}) ->
    NewBlock = NewBlock0#block{signature=Sig},
    [ gen_server:cast({global, name(Dest)}, {block, NewBlock}) || Dest <- lists:seq(0, State#state.n - 1)],
    dispatch(hbbft:next_round(NewHBBFT), State#state{blocks=[NewBlock|State#state.blocks], tempblock=undefined});
dispatch({NewHBBFT, ok}, State) ->
    State#state{hbbft=NewHBBFT};
dispatch({NewHBBFT, Other}, State) ->
    io:format("UNHANDLED ~p~n", [Other]),
    State#state{hbbft=NewHBBFT};
dispatch(Other, State) ->
    io:format("UNHANDLED2 ~p~n", [Other]),
    State.


do_send([], _) ->
    ok;
do_send([{unicast, Dest, Msg}|T], State) ->
    io:format("~p unicasting ~p to ~p~n", [State#state.id, Msg, global:whereis_name(name(Dest))]),
    gen_server:cast({global, name(Dest)}, {hbbft, State#state.id, Msg}),
    do_send(T, State);
do_send([{multicast, Msg}|T], State) ->
    io:format("~p multicasting ~p to ~p~n", [State#state.id, Msg, [global:whereis_name(name(Dest)) || Dest <- lists:seq(0, State#state.n - 1)]]),
    [ gen_server:cast({global, name(Dest)}, {hbbft, State#state.id, Msg}) || Dest <- lists:seq(0, State#state.n - 1)],
    do_send(T, State).

name(N) ->
    list_to_atom(lists:flatten(io_lib:format("hbbft_worker_~b", [N]))).

hash_block(Block) ->
    crypto:hash(sha256, term_to_binary(Block)).
