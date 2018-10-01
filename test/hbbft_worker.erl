-module(hbbft_worker).

-behaviour(gen_server).

-export([start_link/1, submit_transaction/2]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-record(state, {
          relcast :: term(),
          id :: integer(),
          peers :: map()
         }).

start_link(Args) ->
    ID = proplists:get_value(id, Args),
    gen_server:start_link({global, name(ID)}, ?MODULE, Args, []).

submit_transaction(Txn, Pid) ->
    gen_server:call(Pid, {submit_txn, Txn}, infinity).

init(Args) ->
    N = proplists:get_value(n, Args),
    ID = proplists:get_value(id, Args),
    Members = lists:seq(1, N),
    %% init hbbft relcast
    {ok, Relcast} = relcast:start(ID, Members, hbbft_handler, [Args], [{data_dir, "data" ++ integer_to_list(ID)}]),

    Peers = maps:from_list([{I, undefined} || I <- Members, I /= ID ]),

    {ok, do_send(#state{relcast=Relcast, id=ID, peers=Peers})}.

handle_call({submit_txn, Txn}, _From, State=#state{relcast=Relcast0}) ->
    {Resp, Relcast} = relcast:command({txn, Txn}, Relcast0),
    {reply, Resp, do_send(State#state{relcast=Relcast})};
handle_call(Msg, _From, State) ->
    io:format("unhandled msg ~p~n", [Msg]),
    {reply, ok, State}.

handle_cast({hbbft, FromId, Msg}, State) ->
    case relcast:deliver(Msg, FromId, State#state.relcast) of
        {ok, NewRelcast} ->
            gen_server:cast({global, name(FromId)}, {ack, State#state.id}),
            {noreply, do_send(State#state{relcast=NewRelcast})};
        _ ->
            {noreply, State}
    end;
handle_cast({ack, Sender}, State) ->
    ct:pal("ack, Sender: ~p", [Sender]),
    {ok, NewRelcast} = relcast:ack(Sender, maps:get(Sender, State#state.peers, undefined), State#state.relcast),
    {noreply, do_send(State#state{relcast=NewRelcast, peers=maps:put(Sender, undefined, State#state.peers)})};
handle_cast(Msg, State) ->
    io:format("unhandled msg ~p~n", [Msg]),
    {noreply, State}.

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
        not_found ->
            do_send(Tail, State);
        {ok, Ref, Msg, NewRelcast} ->
            gen_server:cast({global, name(I)}, {hbbft, State#state.id, Msg}),
            do_send(Tail, State#state{relcast=NewRelcast, peers=maps:put(I, Ref, State#state.peers)})
    end;
do_send([_ | Tail], State) ->
    do_send(Tail, State).

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
