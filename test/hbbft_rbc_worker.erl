-module(hbbft_rbc_worker).

-behaviour(gen_server).

-record(state, {
          rbc :: hbbft_rbc:rbc_data(),
          n :: non_neg_integer(),
          id :: non_neg_integer(),
          result :: binary(),
          leader :: non_neg_integer()
         }).

-export([start_link/4, get_results/1, input/2]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

start_link(N, F, Id, Leader) ->
    gen_server:start_link({local, name(Id)}, ?MODULE, [N, F, Id, Leader], []).

input(Msg, Pid) ->
    gen_server:cast(Pid, {input, Msg}).

get_results(Pid) ->
    gen_server:call(Pid, get_results, infinity).

%% callbacks

init([N, F, Id, Leader]) ->
    RBC = hbbft_rbc:init(N, F, Id, Leader),
    ct:log("RBC: ~p~n", [RBC]),
    {ok, #state{rbc=RBC, n=N, id=Id, leader=Leader}}.

handle_call(get_results, _From, State) ->
    {reply, State#state.result, State};
handle_call(Msg, _from, State) ->
    ct:log("unhandled msg ~p~n", [Msg]),
    {reply, ok, State}.


handle_cast({input, Msg}, State = #state{rbc=RBC}) ->
    NewState = dispatch(hbbft_rbc:input(RBC, Msg), State),
    {noreply, NewState};
handle_cast({rbc, PeerID, Msg}, State = #state{rbc=RBC}) ->
    NewState = dispatch(hbbft_rbc:handle_msg(RBC, PeerID, Msg), State),
    {noreply, NewState};
handle_cast(Msg, State) ->
    ct:log("unhandled msg ~p~n", [Msg]),
    {noreply, State}.

handle_info(Msg, State) ->
    ct:log("unhandled msg ~p~n", [Msg]),
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
dispatch({NewRBC, {result, Result}}, State) ->
    State#state{result=Result, rbc=NewRBC};
dispatch({NewRBC, ok}, State) ->
    State#state{rbc=NewRBC};
dispatch({NewRBC, Other}, State) ->
    ct:log("UNHANDLED ~p~n", [Other]),
    State#state{rbc=NewRBC};
dispatch(Other, State) ->
    ct:log("UNHANDLED2 ~p~n", [Other]),
    State.

name(X) ->
    list_to_atom(lists:flatten(io_lib:format("rbc_worker_~b", [X]))).
