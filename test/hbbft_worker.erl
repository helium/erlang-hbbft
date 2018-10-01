-module(hbbft_worker).

-behaviour(gen_server).

-export([start_link/1, submit_transaction/2]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-record(state, {
          relcast :: term(),
          id :: integer()
         }).

start_link(Args) ->
    ID = proplists:get_value(id, Args),
    gen_server:start_link({global, name(ID)}, ?MODULE, Args, []).

submit_transaction(Txn, Pid) ->
    gen_server:call(Pid, {submit_txn, Txn}, infinity).

init(Args) ->
    N = proplists:get_value(n, Args),
    ID = proplists:get_value(id, Args),
    %% init hbbft relcast
    {ok, Relcast} = relcast:start(ID, lists:seq(1, N), hbbft_handler, [Args], [{data_dir, "data" ++ integer_to_list(ID)}]),
    {ok, #state{relcast=Relcast, id=ID}}.

handle_call({submit_txn, Txn}, _From, State) ->
    {ok, NewRelcast} = relcast:command({txn, Txn}, State#state.relcast),
    {reply, ok, State#state{relcast=NewRelcast}};
handle_call(Msg, _From, State) ->
    io:format("unhandled msg ~p~n", [Msg]),
    {reply, ok, State}.

handle_cast(Msg, State) ->
    io:format("unhandled msg ~p~n", [Msg]),
    {noreply, State}.

handle_info(Msg, State) ->
    io:format("unhandled msg ~p~n", [Msg]),
    {noreply, State}.

%% helper functions
name(N) ->
    list_to_atom(lists:flatten(["hbbft_worker_", integer_to_list(N)])).

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
