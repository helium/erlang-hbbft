-module(hbbft_relcast_worker).

-behaviour(gen_server).

-export([start_link/1, submit_transaction/2, get_blocks/1, start_on_demand/1, relcast_status/1, status/1]).
-export([verify_chain/2, block_transactions/1, set_filter/2]).

-export([bba_filter/1]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-record(block, {
          prev_hash :: binary(),
          transactions :: [binary()],
          signature :: binary()
         }).

-record(state, {
          relcast :: term(),
          id :: integer(),
          sk :: tc_key_share:tc_key_share(),
          peers :: map(),
          tempblock = undefined :: block(),
          blocks = [] :: [block()],
          filter = fun(_ID, _Msg) -> true end :: fun((any()) -> boolean())
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

init(Args) ->
    N = proplists:get_value(n, Args),
    ID = proplists:get_value(id, Args),
    SK = proplists:get_value(sk, Args),
    DataDir = proplists:get_value(data_dir, Args),
    Members = lists:seq(1, N),
    erlang:send_after(1500, self(), inbound_tick),
    {ok, Relcast} = relcast:start(ID, Members, hbbft_handler, Args,
                                  [{create, true},
                                   {data_dir, DataDir ++ integer_to_list(ID)}]),
    Peers = maps:from_list([{I, undefined} || I <- Members, I /= ID ]),
    {ok, do_send(#state{relcast=Relcast, id=ID, peers=Peers, sk=tc_key_share:deserialize(SK)})}.

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
handle_call(status, From, State) ->
    relcast:command({status, From}, State#state.relcast),
    {noreply, State};
handle_call({set_filter, Fun}, _From, State) ->
    {reply, ok, State#state{filter=Fun}};
handle_call(Msg, _From, State) ->
    ct:log("unhandled msg ~p~n", [Msg]),
    {reply, ok, State}.

handle_cast({hbbft, FromId, Seq, Msg}, State = #state{filter=Filter}) ->
    case Filter(FromId, binary_to_term(Msg)) of
        true ->
            case relcast:deliver(Seq, Msg, FromId, State#state.relcast) of
                {ok, NewRelcast} ->
                    {noreply, do_send(State#state{relcast=NewRelcast})}
            end;
        false ->
            {noreply, State}
    end;
handle_cast({ack, Sender, Seq}, State) ->
    %% ct:pal("ack, Sender: ~p", [Sender]),
    {ok, NewRelcast} = relcast:ack(Sender, Seq, State#state.relcast),
    {noreply, do_send(State#state{relcast=NewRelcast})};
handle_cast({block, Block}, State) ->
    case lists:member(Block, State#state.blocks) of
        false ->
            case verify_block_fit([Block | State#state.blocks], tc_key_share:public_key(State#state.sk)) of
                true ->
                    {ok, Relcast} = relcast:command(next_round, State#state.relcast),
                    {noreply, do_send(State#state{relcast=Relcast,
                                                  tempblock=undefined,
                                                  blocks=[Block | State#state.blocks]
                                                 })
                    };
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

handle_info(inbound_tick, State = #state{relcast=Store}) ->
    case relcast:process_inbound(Store) of
        {ok, Acks, Store1} ->
            dispatch_acks(State#state.id, Acks),
            ok;
        {stop, Timeout, Store1} ->
            erlang:send_after(Timeout, self(), force_close),
            ok
    end,
    erlang:send_after(1500, self(), inbound_tick),
    {noreply, do_send(State#state{relcast=Store1})};
handle_info({transactions, Txns}, State) ->
    %% make sure all the transactions are unique
    ExistingTxns = lists:flatten([ block_transactions(B) || B <- State#state.blocks ]),
    UniqueTxns = Txns -- ExistingTxns,
    NewBlock = new_block(UniqueTxns, State),
    {ok, Relcast} = relcast:command({finalize_round, Txns, term_to_binary(NewBlock)}, State#state.relcast),
    {noreply, do_send(State#state{relcast=Relcast, tempblock=NewBlock})};
handle_info({signature, Sig}, State=#state{tempblock=TempBlock, peers=Peers}) when TempBlock /= undefined ->
    %% ct:pal("Got signature: ~p", [Sig]),
    %% ct:pal("TempBlock: ~p", [TempBlock]),
    NewBlock = TempBlock#block{signature=Sig},
    case lists:member(NewBlock, State#state.blocks) of
        false ->
            case verify_block_fit([NewBlock | State#state.blocks], tc_key_share:public_key(State#state.sk)) of
                true ->
                    _ = [gen_server:cast({global, name(I)}, {block, NewBlock}) || {I, _} <- maps:to_list(Peers)],
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
    ct:log("unhandled msg ~p~n", [Msg]),
    {noreply, State}.

terminate(Reason, State) ->
    relcast:stop(Reason, State#state.relcast),
    ok.

%% helper functions
name(N) ->
    list_to_atom(lists:flatten(["hbbft_worker_", integer_to_list(N)])).

do_send(State) ->
    do_send(maps:to_list(State#state.peers), State).

do_send([], State) ->
    State;
do_send([{I, undefined} | Tail], State) ->
    case relcast:take(I, State#state.relcast, 25) of
        {not_found, NewRelcast} ->
            do_send(Tail, State#state{relcast=NewRelcast});
        {pipeline_full, NewRelcast} ->
            do_send(Tail, State#state{relcast=NewRelcast});
        {ok, Msgs, Acks, NewRelcast} ->
            dispatch_acks(State#state.id, Acks),
            [ gen_server:cast({global, name(I)}, {hbbft, State#state.id, Seq, Msg}) || {Seq, Msg} <- lists:reverse(Msgs)],
            do_send(Tail, State#state{relcast=NewRelcast})
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
            Msg = term_to_binary(A#block{signature= <<>>}),
            Signature = signature:deserialize(A#block.signature),
            case pubkey:verify(PubKey, Signature, Msg) of
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

verify_chain([], _) ->
    true;
verify_chain([G], PubKey) ->
    ct:log("verifying genesis block~n"),
    %% genesis block has no prev hash
    case G#block.prev_hash == <<>> of
        true ->
            %% genesis block should have a valid signature
            Msg = term_to_binary(G#block{signature= <<>>}),
            Signature = signature:deserialize(G#block.signature),
            pubkey:verify(PubKey, Signature, Msg);
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

block_transactions(Block) ->
    Block#block.transactions.

dispatch_acks(_, none) ->
    ok;
dispatch_acks(ID, Acks) ->
    lists:foreach(fun({I, Seqs}) ->
                          [ gen_server:cast({global, name(I)}, {ack, ID, Seq}) || Seq <- Seqs ]
                  end, maps:to_list(Acks)).

