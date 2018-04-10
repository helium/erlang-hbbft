-module(hbbft_worker).

-behaviour(gen_server).

-export([start_link/4, submit_transaction/2, get_blocks/1]).
-export([verify_chain/2, block_transactions/1]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-record(block, {
          prev_hash,
          transactions,
          signature
         }).

-record(state, {
         n,
         id,
         hbbft,
         blocks
        }).

start_link(N, F, ID, SK) ->
    gen_server:start_link({local, name(ID)}, ?MODULE, [N, F, ID, SK], []).

submit_transaction(Msg, Pid) ->
    gen_server:call(Pid, {submit_txn, Msg}, infinity).

get_blocks(Pid) ->
    gen_server:call(Pid, get_blocks, infinity).

verify_chain([G], PubKey) ->
    io:format("verifying genesis block~n"),
    %% genesis block has no prev hash
    true = G#block.prev_hash == <<>>,
    %% genesis block should have a valid signature
    HM = tpke_pubkey:hash_message(PubKey, term_to_binary(G#block{signature= <<>>})),
    Ugh = tpke_pubkey:hash_message(PubKey, <<"ugh">>),
    Signature = erlang_pbc:binary_to_element(Ugh, G#block.signature),
    true = tpke_pubkey:verify_signature(PubKey, Signature, HM);
verify_chain([A, B|_]=Chain, PubKey) ->
    io:format("Chain verification depth ~p~n", [length(Chain)]),
    %% A should have the the prev_hash of B
    true = A#block.prev_hash == hash_block(B),
    %% A should have a valid signature
    HM = tpke_pubkey:hash_message(PubKey, term_to_binary(A#block{signature= <<>>})),
    Ugh = tpke_pubkey:hash_message(PubKey, <<"ugh">>),
    Signature = erlang_pbc:binary_to_element(Ugh, A#block.signature),
    true = tpke_pubkey:verify_signature(PubKey, Signature, HM),
    verify_chain(tl(Chain), PubKey).

block_transactions(Block) ->
    Block#block.transactions.

init([N, F, ID, SK]) ->
    HBBFT = hbbft:init(SK, N, F, ID),
    {ok, #state{hbbft=HBBFT, blocks=[], id=ID, n=N}}.

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
    dispatch(hbbft:finalize_round(NewHBBFT, Txns, term_to_binary(NewBlock)), State#state{blocks=[NewBlock|State#state.blocks]});
dispatch({NewHBBFT, {result, {signature, Sig}}}, State = #state{blocks=[NewBlock|Blocks]}) ->
    dispatch(hbbft:next_round(NewHBBFT), State#state{blocks=[NewBlock#block{signature=Sig}|Blocks]});
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
    gen_server:cast(name(Dest), {hbbft, State#state.id, Msg}),
    do_send(T, State);
do_send([{multicast, Msg}|T], State) ->
    [ gen_server:cast(name(Dest), {hbbft, State#state.id, Msg}) || Dest <- lists:seq(0, State#state.n - 1)],
    do_send(T, State).

name(N) ->
    list_to_atom(lists:flatten(io_lib:format("hbbft_worker_~b", [N]))).

hash_block(Block) ->
    crypto:hash(sha256, term_to_binary(Block)).
