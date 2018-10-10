-module(hbbft_worker).

-behaviour(gen_server).

-export([start_link/1, submit_transaction/2, get_blocks/1, start_on_demand/1, relcast_status/1]).
-export([verify_chain/2, block_transactions/1]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-record(block, {
          prev_hash :: binary(),
          transactions :: [binary()],
          signature :: binary()
         }).

-record(state, {
          relcast :: term(),
          id :: integer(),
          peers :: map(),
          tempblock = undefined :: block(),
          blocks = [] :: [block()]
         }).

-type block() :: #block{}.

start_link(Args) ->
    ID = proplists:get_value(id, Args),
    gen_server:start_link({global, name(ID)}, ?MODULE, Args, []).

submit_transaction(Txn, Pid) ->
    gen_server:call(Pid, {submit_txn, Txn}, infinity).

get_blocks(Pid) ->
    gen_server:call(Pid, get_blocks, infinity).

start_on_demand(Pid) ->
    gen_server:call(Pid, start_on_demand, infinity).

relcast_status(Pid) ->
    gen_server:call(Pid, relcast_status, infinity).

init(Args) ->
    N = proplists:get_value(n, Args),
    ID = proplists:get_value(id, Args),
    DataDir = proplists:get_value(data_dir, Args),
    Members = lists:seq(1, N),
    {ok, Relcast} = relcast:start(ID, Members, hbbft_handler, [Args], [{data_dir, DataDir ++ integer_to_list(ID)}]),
    Peers = maps:from_list([{I, undefined} || I <- Members, I /= ID ]),
    {ok, do_send(#state{relcast=Relcast, id=ID, peers=Peers})}.

handle_call({submit_txn, Txn}, _From, State=#state{relcast=Relcast0}) ->
    {Resp, Relcast} = relcast:command({txn, Txn}, Relcast0),
    {reply, Resp, do_send(State#state{relcast=Relcast})};
handle_call(get_blocks, _From, State) ->
    {reply, {ok, State#state.blocks}, State};
handle_call(start_on_demand, _From, State) ->
    {Resp, Relcast} = relcast:command(start_on_demand, State#state.relcast),
    {reply, Resp, do_send(State#state{relcast=Relcast})};
handle_call(relcast_status, _From, State) ->
    {reply, relcast:status(State#state.relcast), State};
handle_call(Msg, _From, State) ->
    io:format("unhandled msg ~p~n", [Msg]),
    {reply, ok, State}.

handle_cast({hbbft, FromId, Msg}, State) ->
    case relcast:deliver(Msg, FromId, State#state.relcast) of
        {ok, NewRelcast} ->
            gen_server:cast({global, name(FromId)}, {ack, State#state.id}),
            {noreply, do_send(State#state{relcast=NewRelcast})};
        {defer, NewRelcast} ->
            gen_server:cast({global, name(FromId)}, {ack, State#state.id}),
            {noreply, do_send(State#state{relcast=NewRelcast})};
        _ ->
            {noreply, State}
    end;
handle_cast({ack, Sender}, State) ->
    %% ct:pal("ack, Sender: ~p", [Sender]),
    {ok, NewRelcast} = relcast:ack(Sender, maps:get(Sender, State#state.peers, undefined), State#state.relcast),
    {noreply, do_send(State#state{relcast=NewRelcast, peers=maps:put(Sender, undefined, State#state.peers)})};
handle_cast({block, Block, PubKey}, State) ->
    case lists:member(Block, State#state.blocks) of
        false ->
            case verify_block_fit([Block | State#state.blocks], PubKey) of
                true ->
                    {ok, Relcast} = relcast:command(next_round, State#state.relcast),
                    {noreply, do_send(State#state{relcast=Relcast,
                                                  tempblock=undefined,
                                                  blocks=[Block | State#state.blocks]
                                                 })
                    };
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

handle_info({transactions, Txns}, State) ->
    %% ct:pal("Got transactions for creating a new block: ~p", [Txns]),
    NewBlock = new_block(Txns, State),
    {ok, Relcast} = relcast:command({finalize_round, Txns, term_to_binary(NewBlock)}, State#state.relcast),
    {noreply, do_send(State#state{relcast=Relcast, tempblock=NewBlock})};
handle_info({signature, Sig, Pubkey}, State=#state{tempblock=TempBlock, peers=Peers}) when TempBlock /= undefined ->
    %% ct:pal("Got signature: ~p", [Sig]),
    %% ct:pal("TempBlock: ~p", [TempBlock]),
    NewBlock = TempBlock#block{signature=Sig},
    case lists:member(NewBlock, State#state.blocks) of
        false ->
            case verify_block_fit([NewBlock | State#state.blocks], Pubkey) of
                true ->
                    _ = [gen_server:cast({global, name(I)}, {block, NewBlock, Pubkey}) || {I, _} <- maps:to_list(Peers)],
                    {ok, Relcast} = relcast:command(next_round, State#state.relcast),
                    {noreply, do_send(State#state{relcast=Relcast,
                                                  tempblock=undefined,
                                                  blocks=[NewBlock | State#state.blocks]
                                                 })
                    };
                false ->
                    {noreply, State}
            end;
        true ->
            {noreply, State}
    end;
handle_info(Msg, State) ->
    io:format("unhandled msg ~p~n", [Msg]),
    {noreply, State}.

%% helper functions
name(N) ->
    list_to_atom(lists:flatten(["hbbft_worker_", integer_to_list(N)])).

do_send(State) ->
    do_send(maps:to_list(State#state.peers), State).

do_send([], State) ->
    State;
do_send([{I, undefined} | Tail], State) ->
    case relcast:take(I, State#state.relcast) of
        {not_found, NewRelcast} ->
            do_send(Tail, State#state{relcast=NewRelcast});
        {ok, Ref, Msg, NewRelcast} ->
            gen_server:cast({global, name(I)}, {hbbft, State#state.id, Msg}),
            do_send(Tail, State#state{relcast=NewRelcast, peers=maps:put(I, Ref, State#state.peers)})
    end;
do_send([_ | Tail], State) ->
    do_send(Tail, State).

new_block(Txns, State) ->
    case State#state.blocks of
        [] ->
            %% genesis block
            #block{prev_hash= <<>>, transactions=Txns, signature= <<>>};
        [PrevBlock|_Blocks] ->
            #block{prev_hash=hash_block(PrevBlock), transactions=Txns, signature= <<>>}
    end.

hash_block(Block) ->
    crypto:hash(sha256, term_to_binary(Block)).

verify_block_fit([B], _) when B#block.prev_hash == <<>> -> true;
verify_block_fit([A, B | _], PubKey) ->
    %% A should have the the prev_hash of B
    case A#block.prev_hash == hash_block(B) of
        true ->
            %% A should have a valid signature
            HM = tpke_pubkey:hash_message(PubKey, term_to_binary(A#block{signature= <<>>})),
            Signature = tpke_pubkey:deserialize_element(PubKey, A#block.signature),
            case tpke_pubkey:verify_signature(PubKey, Signature, HM) of
                true ->
                    true;
                false ->
                    io:format("bad signature~n"),
                    false
            end;
        false ->
            io:format("parent hash mismatch ~p ~p~n", [A#block.prev_hash, hash_block(B)]),
            false
    end.

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
verify_chain(Chain, PubKey) ->
    io:format("Chain verification depth ~p~n", [length(Chain)]),
    case verify_block_fit(Chain, PubKey) of
        true -> verify_chain(tl(Chain), PubKey);
        false ->
            io:format("bad signature~n"),
            false
    end.

block_transactions(Block) ->
    Block#block.transactions.
