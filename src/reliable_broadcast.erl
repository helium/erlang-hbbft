-module(reliable_broadcast).

-behaviour(gen_statem).

-export([start/0, input/1, get_val/0, stop/0]).
-export([random_n/2]).
-export([terminate/3, code_change/4, init/1, callback_mode/0, handle_event/4]).

%% TODO: better names
-record(data, {
          n :: pos_integer(),
          f :: pos_integer(),
          msg = undefined :: binary() | undefined,
          h = undefined :: binary() | undefined,
          shares = [] :: [{merkerl:proof(), binary()}],
          num_echoes = sets:new() :: sets:set(non_neg_integer()),
          num_readies = sets:new() :: sets:set(non_neg_integer())
         }).

-type val_msg() :: {val, merkerl:hash(), merkerl:proof(), binary()}.
-type echo_msg() :: {echo, merkerl:hash(), merkerl:proof(), binary()}.
-type ready_msg() :: {ready, merkerl:hash()}.

-type multicast() :: {multicast, echo_msg() | ready_msg()}.
-type unicast() :: {unicast, J :: non_neg_integer(), val_msg()}.
-type send_commands() :: [unicast() | multicast()].

%% API.
start(N, F) ->
    gen_statem:start(?MODULE, [N, F], []).

-spec input(pid(), binary()) -> {send, send_commands()} | {error, already_initialized}.
input(Pid, Msg) ->
    gen_statem:call(Pid, {input, Msg}).

-spec val(pid(), merkerl:hash(), merkerl:proof(), binary()) -> ok | {send, send_commands()}.
val(Pid, H, Bi, Si) ->
    gen_statem:call(Pid, {val, H, Bi, Si}).

-spec echo(pid(), merkerl:hash(), merkerl:proof(), binary()) -> ok | {send, send_commands()} | {result, V :: binary()} | abort.
echo(Pid, H, Bi, Si) ->
    gen_statem:call(Pid, {echo, H, Bi, Si}).

-spec ready(pid(), merkerl:hash()) -> ok | {send, send_commands()} | {result, V :: binary()}.
ready(Pid, H) ->
    gen_statem:call(Pid, {ready, H}).


-spec get_val(pid()) -> any().
get_val(Pid) ->
    gen_statem:call(Pid, get_val).

stop() ->
    gen_statem:stop(name()).

%% Mandatory callback functions
terminate(_Reason, _State, _Data) ->
    void.

code_change(_Vsn, State, Data, _Extra) ->
    {ok, State, Data}.

init([N, F]) ->
    State = init, Data = #data{n=N, f=F},
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
    {next_state, waiting_for_echo, NewData, [{reply, From, {send, [{multicast, {echo, MerkleRootHash, hd(BranchesForShards), hd(Shards}} | Result]}}]};
handle_event({call, From}, {val, J, H, Bj, Sj}, init, Data = #data{shares=[]}) ->
    NewData = Data#data{h=H, shares=[{Bj, Sj}]},
    {next_state, waiting_for_echo, NewData, [{reply, From, {send, [{multicast, {echo, H, Bj, Sj}}]}}]};
handle_event({call, From}, {echo, J, H, Bj, Sj}, init, Data = #data{n=N, f=F}) ->
    %% TODO echoes need to be *distinct* somehow
    %%
    %% Check that Bj is a valid merkle branch for root h and and leaf Sj
    case merkerl:verify_proof(merkerl:hash_value(Sj), H, Bj) of
        ok ->
            NewData = Data#data{h=H, shares=lists:usort([{Bj, Sj}|Data#data.shares], num_echoes=sets:add_element(J, Data#data.num_echoes)},
            case sets:size(NewData#data.num_echoes) >= (N - F) of
                true ->
                    %% interpolate Sj from any N-2f leaves received
                    Threshold = N - 2*F,
                    {_, Shards} = lists:unzip(NewData#data.shares),
                    case leo_erasure:decode({Threshold, N - Threshold}, NewData#data.shares, Size) of
                        {ok, Msg} ->
                            %% recompute merkle root H
            {keep_state, NewData, [{reply, From, ok}]};
        {error, _} ->
            %% otherwise discard
            {keep_state_and_data, [{reply, From, ok}]}
    end;
handle_event({call, From}, {val, _, _, _}, waiting_for_echo, _Data) ->
    %% we already had a val, just ignore this
    {keep_state_and_data, [{reply, From, ok}]}.
handle_event({call, From}, {val, {N, F, Msg}}, init, _Data) ->
handle_event({call, From}, get_val, State, Data) ->
    {next_state, State, Data, [{reply, From, Data}]}.

%% helpers
random_n(N, List) ->
    lists:sublist(shuffle(List), N).

shuffle(List) ->
    [X || {_,X} <- lists:sort([{rand:uniform(), N} || N <- List])].


-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

init_test() ->
    {ok, _Pid} = reliable_broadcast:start(),
    %% merkle should not be constructed yet
    #data{br=NoBr} = reliable_broadcast:get_val(),
    ?assertEqual(NoBr, undefined),
    N = 14,
    F = 4,
    Msg = crypto:strong_rand_bytes(512),
    reliable_broadcast:input(N, F, Msg),
    %% there must be some branches now
    #data{br=Br, sj=Sj} = reliable_broadcast:get_val(),
    ?assertNotEqual(Br, undefined),
    ?assertEqual(length(Br), length(Sj)),
    ok.

-endif.
