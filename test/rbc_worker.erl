-module(rbc_worker).

-behaviour(gen_server).

-record(state, {
          rbc,
          n,
          id,
          results
         }).

-export([start_link/3, get_results/2]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

start_link(N, F, Id) ->
    gen_server:start_link({local, name(Id)}, ?MODULE, [N, F, Id], []).


get_results(Msg, Pid) ->
    gen_server:call(Pid, {get_results, Msg}, infinity).


%% callbacks

init([N, F, Id]) ->
    RBC = reliable_broadcast:init(N, F),
    {ok, #state{rbc=RBC, results=[], n=N, id=Id}}.

handle_call({get_results, Msg}, _From, State=#state{rbc=RBC}) ->
    NewState = dispatch(reliable_broadcast:input(RBC, Msg), State),
    {reply, ok, NewState};
handle_call(Msg, _from, State) ->
    io:format("unhandled msg ~p~n", [Msg]),
    {reply, ok, State}.

handle_cast({rbc, PeerID, Msg}, State = #state{rbc=RBC}) ->
    NewState = dispatch(reliable_broadcast:handle_msg(RBC, PeerID, Msg), State),
    {noreply, NewState};
handle_cast(Msg, State) ->
    io:format("unhandled msg ~p~n", [Msg]),
    {noreply, State}.

handle_info(Msg, State) ->
    io:format("unhandled msg ~p~n", [Msg]),
    {noreply, State}.


%% helper funcs

do_send([], _) ->
    ok;
do_send([{unicast, Dest, Msg}|T], State) ->
    gen_server:cast(name(Dest), {rbc, State#state.id, Msg}),
    do_send(T, State);
do_send([{multicast, Msg}|T], State) ->
    [ gen_server:cast(name(Dest), {rbc, State#state.id, Msg}) || Dest <- lists:seq(0, State#state.n - 1)],
    do_send(T, State).

dispatch({NewRBC, {send, ToSend}}, State) ->
    do_send(ToSend, State),
    State#state{rbc=NewRBC};
dispatch({_NewRBC, {result, Result}}, State) ->
    State#state{results=[Result | State#state.results]};
dispatch({NewRBC, ok}, State) ->
    State#state{rbc=NewRBC};
dispatch({NewRBC, Other}, State) ->
    io:format("UNHANDLED ~p~n", [Other]),
    State#state{rbc=NewRBC};
dispatch(Other, State) ->
    io:format("UNHANDLED2 ~p~n", [Other]),
    State.

name(X) ->
    list_to_atom(lists:flatten(io_lib:format("rbc_worker_~b", [X]))).
