-module(reliable_broadcast).

-behaviour(gen_statem).

-export([start_link/3, input/2, val/4, echo/5, ready/3, stop/1]).
-export([random_n/2]).
-export([terminate/3, code_change/4, init/1, callback_mode/0, handle_event/4]).

-record(data, {
          n :: pos_integer(),
          f :: pos_integer(),
          size :: pos_integer(),
          msg = undefined :: binary() | undefined,
          h = undefined :: binary() | undefined,
          shares = [] :: [{merkerl:proof(), binary()}],
          num_echoes = sets:new() :: sets:set(non_neg_integer()),
          num_readies = sets:new() :: sets:set(non_neg_integer()),
          ready_sent = false :: boolean()
         }).

-type val_msg() :: {val, merkerl:hash(), merkerl:proof(), binary()}.
-type echo_msg() :: {echo, merkerl:hash(), merkerl:proof(), binary()}.
-type ready_msg() :: {ready, merkerl:hash()}.

-type multicast() :: {multicast, echo_msg() | ready_msg()}.
-type unicast() :: {unicast, J :: non_neg_integer(), val_msg()}.
-type send_commands() :: [unicast() | multicast()].

%% API.
start_link(N, F, Size) ->
    gen_statem:start_link(?MODULE, [N, F, Size], []).

-spec input(pid(), binary()) -> {send, send_commands()} | {error, already_initialized}.
input(Pid, Msg) ->
    gen_statem:call(Pid, {input, Msg}).

-spec val(pid(), merkerl:hash(), merkerl:proof(), binary()) -> ok | {send, send_commands()}.
val(Pid, H, Bi, Si) ->
    gen_statem:call(Pid, {val, H, Bi, Si}).

-spec echo(pid(), non_neg_integer(), merkerl:hash(), merkerl:proof(), binary()) -> ok | {send, send_commands()} | {result, V :: binary()} | abort.
echo(Pid, J, H, Bi, Si) ->
    gen_statem:call(Pid, {echo, J, H, Bi, Si}).

-spec ready(pid(), non_neg_integer(), merkerl:hash()) -> ok | {send, send_commands()} | {result, V :: binary()}.
ready(Pid, J, H) ->
    gen_statem:call(Pid, {ready, J, H}).

stop(Pid) ->
    gen_statem:stop(Pid).

%% Mandatory callback functions
terminate(_Reason, _State, _Data) ->
    void.

code_change(_Vsn, State, Data, _Extra) ->
    {ok, State, Data}.

init([N, F, Size]) ->
    State = init, Data = #data{n=N, f=F, size=Size},
    {ok, State, Data}.

callback_mode() -> handle_event_function.

%% state callback(s)
handle_event({call, From}, {input, Msg}, init, Data =#data{n=N, f=F}) ->
    %% Figure2 from honeybadger WP
    %%%% let {Sj} j∈[N] be the blocks of an (N − 2 f , N)-erasure coding
    %%%% scheme applied to v
    %%%% let h be a Merkle tree root computed over {Sj}
    %%%% send VAL(h, b j , s j ) to each party P j , where b j is the jth
    %%%% Merkle tree branch
    Threshold = N - 2*F,
    {ok, Shards} = leo_erasure:encode({Threshold, N - Threshold}, Msg),
    Merkle = merkerl:new(Shards, fun merkerl:hash_value/1),
    MerkleRootHash = merkerl:root_hash(Merkle),
    %% gen_proof = branches for each merkle node (Hash(shard))
    BranchesForShards = [merkerl:gen_proof(Hash, Merkle) || {Hash, _} <- merkerl:leaves(Merkle)],
    %% TODO add our identity to the ready/echo sets?
    NewData = Data#data{msg=Msg, h=MerkleRootHash},
    Result = [ {unicast, J, {val, MerkleRootHash, lists:nth(J+1, BranchesForShards), lists:nth(J+1, Shards)}} || J <- lists:seq(1, N-1)],
    %% unicast all the VAL packets and multicast the ECHO for our own share
    {next_state, waiting, NewData, [{reply, From, {send, [{multicast, {echo, MerkleRootHash, hd(BranchesForShards), hd(Shards)}} | Result]}}]};
handle_event({call, From}, {val, H, Bj, Sj}, init, Data = #data{shares=[]}) ->
    NewData = Data#data{h=H, shares=[{Bj, Sj}]},
    {next_state, waiting, NewData, [{reply, From, {send, [{multicast, {echo, H, Bj, Sj}}]}}]};
handle_event({call, From}, {echo, J, H, Bj, Sj}, _State, Data = #data{n=N, f=F}) ->
    %% TODO echoes need to be *distinct* somehow
    %%
    %% Check that Bj is a valid merkle branch for root h and and leaf Sj
    case merkerl:verify_proof(merkerl:hash_value(Sj), H, Bj) of
        ok ->
            NewData = Data#data{h=H, shares=lists:usort([{Bj, Sj}|Data#data.shares]), num_echoes=sets:add_element(J, Data#data.num_echoes)},
            case sets:size(NewData#data.num_echoes) >= (N - F) of
                true ->
                    %% interpolate Sj from any N-2f leaves received
                    Threshold = N - 2*F,
                    {_, Shards} = lists:unzip(NewData#data.shares),
                    case leo_erasure:decode({Threshold, N - Threshold}, NewData#data.shares, NewData#data.size) of
                        {ok, Msg} ->
                            %% recompute merkle root H
                            Merkle = merkerl:new(Shards, fun merkerl:hash_value/1),
                            MerkleRootHash = merkerl:root_hash(Merkle),
                            case H == MerkleRootHash of
                                true ->
                                    %% root hashes match
                                    %% check if ready already sent
                                    case NewData#data.ready_sent of
                                        true ->
                                            %% check if we have enough readies and enough echoes
                                            %% N-2F echoes and 2F + 1 readies
                                            case sets:size(NewData#data.num_echoes) >= Threshold andalso sets:size(NewData#data.num_readies) >= 2*F + 1 of
                                                true ->
                                                    %% decode V. Done
                                                    {stop_and_reply, normal, [{reply, From, {result, Msg}}]};
                                                false ->
                                                    %% wait for enough echoes and readies?
                                                    {next_state, waiting, NewData#data{msg=Msg}}
                                            end;
                                        false ->
                                            %% send ready(h)
                                            {next_state, waiting, NewData#data{msg=Msg}, [{reply, From, {send, [{multicast, {ready, H}}]}}]}
                                    end;
                                false ->
                                    %% abort
                                    {stop_and_reply, NewData, [{reply, From, abort}]}
                            end;
                        {error, _} ->
                            {next_state, waiting, NewData, [{reply, From, ok}]}
                    end;
                false ->
                    {next_state, waiting, NewData, [{reply, From, ok}]}
            end;
        {error, _} ->
            %% otherwise discard
            {keep_state_and_data, [{reply, From, ok}]}
    end;
handle_event({call, From}, {ready, J, H}, waiting, #data{h=H, n=N, f=F}=Data) ->
    %% TODO increment num_readies
    NewData = Data#data{num_readies=sets:add_element(J, Data#data.num_readies)},
    case sets:size(NewData#data.num_readies) >= F + 1 of
        true ->
            Threshold = N - 2*F,
            %% check if we have 2*F + 1 readies and N - 2*F echoes
            case sets:size(NewData#data.num_echoes) >= Threshold andalso sets:size(NewData#data.num_readies) >= 2*F + 1 of
                true ->
                    %% done
                    {stop_and_reply, normal, [{reply, From, {result, NewData#data.msg}}]};
                false when not NewData#data.ready_sent ->
                    %% multicast ready
                    {next_state, waiting, NewData#data{ready_sent=true}, [{reply, From, {send, [{multicast, {ready, H}}]}}]};
                _ ->
                    {next_state, waiting, NewData, [{reply, From, ok}]}
            end;
        false ->
            %% waiting
            {keep_state_and_data, [{reply, From, ok}]}
    end;
handle_event({call, From}, {val, _, _, _, _}, waiting, _Data) ->
    %% we already had a val, just ignore this
    {keep_state_and_data, [{reply, From, ok}]};
handle_event({call, From}, {ready, _, _}, init, _Data) ->
    %% ignore a ready before we know what we're doing
    {keep_state_and_data, [{reply, From, ok}]}.

%% helpers
random_n(N, List) ->
    lists:sublist(shuffle(List), N).

shuffle(List) ->
    [X || {_,X} <- lists:sort([{rand:uniform(), N} || N <- List])].


-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

init_test() ->
    N = 5,
    F = 1,
    Msg = crypto:strong_rand_bytes(512),
    {ok, Pid0} = reliable_broadcast:start_link(N, F, 512),
    {ok, Pid1} = reliable_broadcast:start_link(N, F, 512),
    {ok, Pid2} = reliable_broadcast:start_link(N, F, 512),
    {ok, Pid3} = reliable_broadcast:start_link(N, F, 512),
    {ok, Pid4} = reliable_broadcast:start_link(N, F, 512),
    Pids = [Pid0, Pid1, Pid2, Pid3, Pid4],
    {send, MsgsToSend} = reliable_broadcast:input(Pid0, Msg),
    ?debugFmt("MsgsToSend ~p~n", [MsgsToSend]),
    AThing = do_send_outer([{0, {send, MsgsToSend}}], Pids),
    ?debugFmt("A Thing ~p~n", [AThing]),
    ?assert(false),
    ok.

do_send_outer([], _) ->
    ok;
do_send_outer([H|T], Pids) ->
    R = do_send(H, Pids),
    ?debugFmt("Round output ~p~n", [R]),
    ?debugFmt("Round output 1~p~n", [hd(R)]),
    do_send_outer(T++[R], Pids).

do_send({_, {send, []}}, _) ->
    [];
do_send({Id, {send, [{unicast, J, {val, H, Bj, Sj}}|T]}}, Pids) ->
    Destination = lists:nth(J+1, Pids),
    [{J, val(Destination, H, Bj, Sj)}] ++ do_send({Id, {send, T}}, Pids);
do_send({Id, {send, [{multicast, Msg}|T]}}, Pids) ->
    case Msg of
        {echo, H, Bj, Sj} ->
            PidsWithId = lists:zip(lists:seq(0, length(Pids) - 1), Pids),
            [{J, echo(P, Id, H, Bj, Sj)} || {J, P} <- Pids, J /= Id] ++ do_send({Id, {send, T}}, Pids);
        {ready, H} ->
            PidsWithId = lists:zip(lists:seq(0, length(Pids) - 1), Pids),
            [{J, ready(P, Id, H)} || {J, P} <- Pids, J /= Id] ++ do_send({Id, {send, T}}, Pids)
    end.

-endif.
