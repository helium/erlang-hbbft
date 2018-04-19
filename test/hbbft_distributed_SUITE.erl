-module(hbbft_distributed_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("kernel/include/inet.hrl").

-export([
         init_per_suite/1,
         end_per_suite/1,
         init_per_testcase/2,
         end_per_testcase/2,
         all/0
        ]).

-export([simple_test/1]).

%% common test callbacks

all() -> [simple_test].

init_per_suite(Config) ->
    os:cmd(os:find_executable("epmd")++" -daemon"),
    {ok, Hostname} = inet:gethostname(),
    case net_kernel:start([list_to_atom("runner@"++Hostname), shortnames]) of
        {ok, _} -> ok;
        {error, {already_started, _}} -> ok;
        {error, {{already_started, _},_}} -> ok
    end,
    Config.

end_per_suite(Config) ->
    %% per suite cleanup, placeholder
    Config.

init_per_testcase(TestCase, Config) ->
    %% assuming each testcase will work with 5 nodes for now
    NodeNames = [eric, kenny, kyle, ike, stan],
    Nodes = hbbft_ct_utils:pmap(fun(Node) ->
                                        hbbft_ct_utils:start_node(Node, Config, TestCase)
                                end, NodeNames),

    _ = [hbbft_ct_utils:connect(Node) || Node <- NodeNames],

    {ok, _} = ct_cover:add_nodes(Nodes),
    [{nodes, Nodes} | Config].

end_per_testcase(_TestCase, Config) ->
    Nodes = proplists:get_value(nodes, Config),
    hbbft_ct_utils:pmap(fun(Node) -> ct_slave:stop(Node) end, Nodes),
    ok.

%% test cases

simple_test(Config) ->
    Nodes = proplists:get_value(nodes, Config),

    %% master starts the dealer
    N = length(Nodes),
    F = (N div 3),
    dealer:start_link(N, F+1, 'SS512'),
    {ok, PubKey, PrivateKeys} = dealer:deal(),
    gen_server:stop(dealer),

    %% each node gets a secret key
    NodesSKs = lists:zip(Nodes, PrivateKeys),

    %% load hbbft_worker on each node
    {Mod, Bin, _} = code:get_object_code(hbbft_worker),
    _ = hbbft_ct_utils:pmap(fun(Node) ->
                                    rpc:call(Node, erlang, load_module, [Mod, Bin])
                            end, Nodes),

    %% start a hbbft_worker on each node
    Workers = [{Node, rpc:call(Node, hbbft_worker, start_link, [N, F, I, tpke_privkey:serialize(SK)])} || {I, {Node, SK}} <- enumerate(NodesSKs)],
    ok = global:sync(),

    io:format("LOL ~p ~n", [global:whereis_name(hbbft_worker_0)]),

    %% bunch of msgs
    Msgs = [ crypto:strong_rand_bytes(128) || _ <- lists:seq(1, N*20)],

    %% feed the nodes some msgs
    lists:foreach(fun(Msg) ->
                          Destinations = random_n(rand:uniform(N), Workers),
                          io:format("destinations ~p~n", [Destinations]),
                          [rpc:call(Node, hbbft_worker, submit_transaction, [Msg, Destination]) || {Node, {ok, Destination}} <- Destinations]
                  end, Msgs),

    timer:sleep(30000),
    Chains = sets:from_list(lists:map(fun({Node, {ok, Worker}}) ->
                                              {ok, Blocks} = rpc:call(Node, hbbft_worker, get_blocks, [Worker]),
                                              Blocks
                                      end, Workers)),
    1 = sets:size(Chains),
    true = (0 /= length(hd(sets:to_list(Chains)))),

    %% just printing the chain
    [Chain] = sets:to_list(Chains),
    io:format("Chain: ~p~n", [Chain]),
    io:format("chain is of height ~p~n", [length(Chain)]),

    %% verify they are cryptographically linked,
    hbbft_worker:verify_chain(Chain, tpke_pubkey:serialize(PubKey)),

    %% check all transactions are unique
    BlockTxns = lists:flatten([ hbbft_worker:block_transactions(B) || B <- Chain ]),
    true = length(BlockTxns) == sets:size(sets:from_list(BlockTxns)),

    %% check they're all members of the original message list
    true = sets:is_subset(sets:from_list(BlockTxns), sets:from_list(Msgs)),
    io:format("chain contains ~p distinct transactions~n", [length(BlockTxns)]),
    ok.

%% helpers
enumerate(List) ->
    lists:zip(lists:seq(0, length(List) - 1), List).

random_n(N, List) ->
    lists:sublist(shuffle(List), N).

shuffle(List) ->
    [X || {_,X} <- lists:sort([{rand:uniform(), N} || N <- List])].
