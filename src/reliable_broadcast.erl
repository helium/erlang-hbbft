-module(reliable_broadcast).

-behaviour(gen_statem).

-export([start/0, input/3, get_val/0, stop/0]).
-export([random_n/2]).
-export([terminate/3, code_change/4, init/1, callback_mode/0, handle_event/4]).

%% TODO: better names
-record(data, {
          n = undefined,
          f = undefined,
          msg = undefined,
          sj = undefined,
          h = undefined,
          br = undefined
         }).

name() -> rbc_statem.

%% API.
start() ->
    gen_statem:start({local,name()}, ?MODULE, [], []).

-spec input(pos_integer(), pos_integer(), binary()) -> #data{}.
input(N, F, Msg) ->
    gen_statem:call(name(), {input, {N, F, Msg}}).

get_val() ->
    gen_statem:call(name(), get_val).

stop() ->
    gen_statem:stop(name()).

%% Mandatory callback functions
terminate(_Reason, _State, _Data) ->
    void.
code_change(_Vsn, State, Data, _Extra) ->
    {ok, State, Data}.
init([]) ->
    State = init, Data = #data{},
    {ok, State, Data}.
callback_mode() -> handle_event_function.

%% state callback(s)
handle_event({call, From}, {input, {N, F, Msg}}, init, _Data) ->
    %% Figure2 from honeybadger WP
    %%%% let {Sj} j∈[N] be the blocks of an (N − 2 f , N)-erasure coding
    %%%% scheme applied to v
    %%%% let h be a Merkle tree root computed over {Sj}
    %%%% send VAL(h, b j , s j ) to each party P j , where b j is the jth
    %%%% Merkle tree branch
	Threshold = N - 2*F,
	{ok, Shards} = leo_erasure:encode({Threshold, N}, Msg),
    Merkle = merkerl:new(Shards, fun merkerl:hash_value/1),
    MerkleRootHash = merkerl:root_hash(Merkle),
    %% gen_proof = branches for each merkle node (Hash(shard))
    BranchesForShards = [merkerl:gen_proof(Hash, Merkle) || {Hash, _} <- merkerl:leaves(Merkle)],
    NewData = #data{n=N, f=F, msg=Msg, h=MerkleRootHash, br=BranchesForShards, sj=Shards},
    {next_state, waiting_for_val, NewData, [{reply, From, NewData}]};
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
