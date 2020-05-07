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

-export([simple_test/1, serialization_test/1, partition_test/1, partition_and_filter_test/1]).

%% common test callbacks

all() -> [simple_test, serialization_test, partition_test, partition_and_filter_test].

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
    %% assuming each testcase will work with 4 nodes for now
    NodeNames = [eric, kenny, kyle, stan],
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
    BatchSize = 20,
    {ok, Dealer} = dealer:new(N, F+1, 'SS512'),
    {ok, {PubKey, PrivateKeys}} = dealer:deal(Dealer),

    %% each node gets a secret key
    NodesSKs = lists:zip(Nodes, PrivateKeys),

    %% load hbbft_worker on each node
    {Mod, Bin, _} = code:get_object_code(hbbft_worker),
    _ = hbbft_ct_utils:pmap(fun(Node) ->
                                    rpc:call(Node, erlang, load_module, [Mod, Bin])
                            end, Nodes),

    %% start a hbbft_worker on each node
    Workers = [{Node, rpc:call(Node, hbbft_worker, start_link, [N, F, I, tpke_privkey:serialize(SK), BatchSize, false])} || {I, {Node, SK}} <- enumerate(NodesSKs)],
    ok = global:sync(),

    [ link(W) || {_, {ok, W}} <- Workers ],

    %% bunch of msgs
    Msgs = [ crypto:strong_rand_bytes(128) || _ <- lists:seq(1, N*20)],

    %% feed the nodes some msgs
    lists:foreach(fun(Msg) ->
                          Destinations = random_n(rand:uniform(N), Workers),
                          ct:pal("destinations ~p~n", [Destinations]),
                          [hbbft_worker:submit_transaction(Msg, Destination) || {_Node, {ok, Destination}} <- Destinations]
                  end, Msgs),

    %% wait for all the worker's mailboxes to settle and.
    %% wait for the chains to converge
    ok = hbbft_ct_utils:wait_until(fun() ->
                                           Chains = lists:map(fun({_Node, {ok, W}}) ->
                                                                      {ok, Blocks} = hbbft_worker:get_blocks(W),
                                                                      Blocks
                                                              end, Workers),

                                           lists:all(fun(C) -> length(C) > 1 end, Chains)
                                   end, 60*2, 500),


    AllChains = lists:map(fun({_Node, {ok, W}}) ->
                               {ok, Blocks} = hbbft_worker:get_blocks(W),
                               Blocks
                       end, Workers),
    %% find the shortest chain and check all chains have the same common prefix
    ShortestChainLen = hd(lists:sort([ length(C) || C <- AllChains ])),

    Chains = sets:from_list(lists:map(fun(C) -> lists:reverse(lists:sublist(lists:reverse(C), ShortestChainLen)) end, AllChains)),

    ct:pal("~p distinct chains~n", [sets:size(Chains)]),
    %true = (2 > sets:size(Chains)),
    %true = (2 < length(hd(sets:to_list(Chains)))),

    lists:foreach(fun(Chain) ->
                          %ct:pal("Chain: ~p~n", [Chain]),
                          ct:pal("chain is of height ~p~n", [length(Chain)]),

                          %% verify they are cryptographically linked,
                          true = hbbft_worker:verify_chain(Chain, PubKey),

                          %% check all transactions are unique
                          BlockTxns = lists:flatten([ hbbft_worker:block_transactions(B) || B <- Chain ]),
                          true = length(BlockTxns) == sets:size(sets:from_list(BlockTxns)),

                          %% check they're all members of the original message list
                          true = sets:is_subset(sets:from_list(BlockTxns), sets:from_list(Msgs)),
                          ct:pal("chain contains ~p distinct transactions~n", [length(BlockTxns)])
                  end, sets:to_list(Chains)),

    %% check we actually converged and made a chain

    true = (1 == sets:size(Chains)),
    true = (0 < length(hd(sets:to_list(Chains)))),

    [ unlink(W) || {_, {ok, W}} <- Workers ],
    ok.

serialization_test(Config) ->
    Nodes = proplists:get_value(nodes, Config),

    %% master starts the dealer
    N = length(Nodes),
    F = (N div 3),
    BatchSize = 20,
    {ok, Dealer} = dealer:new(N, F+1, 'SS512'),
    {ok, {PubKey, PrivateKeys}} = dealer:deal(Dealer),

    %% each node gets a secret key
    NodesSKs = lists:zip(Nodes, PrivateKeys),

    %% load hbbft_worker on each node
    {Mod, Bin, _} = code:get_object_code(hbbft_worker),
    _ = hbbft_ct_utils:pmap(fun(Node) ->
                                    rpc:call(Node, erlang, load_module, [Mod, Bin])
                            end, Nodes),

    %% start a hbbft_worker on each node
    Workers = [{Node, rpc:call(Node, hbbft_worker, start_link, [N, F, I, tpke_privkey:serialize(SK), BatchSize, false])} || {I, {Node, SK}} <- enumerate(NodesSKs)],
    ok = global:sync(),

    [ link(W) || {_, {ok, W}} <- Workers ],

    %% bunch of msgs
    Msgs = [ crypto:strong_rand_bytes(128) || _ <- lists:seq(1, N*20)],

    %% feed the nodes some msgs
    lists:foreach(fun(Msg) ->
                          Destinations = random_n(rand:uniform(N), Workers),
                          ct:pal("destinations ~p~n", [Destinations]),
                          [hbbft_worker:submit_transaction(Msg, Destination) || {_Node, {ok, Destination}} <- Destinations]
                  end, Msgs),

    %% wait for all the worker's mailboxes to settle and.
    %% wait for the chains to converge
    ok = hbbft_ct_utils:wait_until(
           fun() ->
                   Chains = lists:map(fun({_Node, {ok, W}}) ->
                                              {ok, Blocks} = hbbft_worker:get_blocks(W),
                                              Blocks
                                      end, Workers),
                   lists:all(fun(C) -> length(C) > 1 end, Chains)
           end, 60*2, 500),


    AllChains = lists:map(fun({_Node, {ok, W}}) ->
                               {ok, Blocks} = hbbft_worker:get_blocks(W),
                               Blocks
                       end, Workers),
    %% find the shortest chain and check all chains have the same common prefix
    ShortestChainLen = hd(lists:sort([ length(C) || C <- AllChains ])),

    Chains = sets:from_list(lists:map(fun(C) -> lists:reverse(lists:sublist(lists:reverse(C), ShortestChainLen)) end, AllChains)),

    ct:pal("~p distinct chains~n", [sets:size(Chains)]),
    %true = (2 > sets:size(Chains)),
    %true = (2 < length(hd(sets:to_list(Chains)))),

    lists:foreach(fun(Chain) ->
                          %ct:pal("Chain: ~p~n", [Chain]),
                          ct:pal("chain is of height ~p~n", [length(Chain)]),

                          %% verify they are cryptographically linked,
                          true = hbbft_worker:verify_chain(Chain, PubKey),

                          %% check all transactions are unique
                          BlockTxns = lists:flatten([ hbbft_worker:block_transactions(B) || B <- Chain ]),
                          true = length(BlockTxns) == sets:size(sets:from_list(BlockTxns)),

                          %% check they're all members of the original message list
                          true = sets:is_subset(sets:from_list(BlockTxns), sets:from_list(Msgs)),
                          ct:pal("chain contains ~p distinct transactions~n", [length(BlockTxns)])
                  end, sets:to_list(Chains)),

    %% check we actually converged and made a chain

    true = (1 == sets:size(Chains)),
    true = (0 < length(hd(sets:to_list(Chains)))),

    [ unlink(W) || {_, {ok, W}} <- Workers ],
    ok.

%% partition the first node from f other nodes
partition_test(Config) ->
    partition_test_(Config, undefined).

%% partition the first node from f other nodes and filter *all* BBA messages from the partitioned node on all other nodes
partition_and_filter_test(Config) ->
    %% filter out all BBA messages from identity 1
    partition_test_(Config, hbbft_worker:bba_filter(1)).

partition_test_(Config, Filter) ->
    Nodes = proplists:get_value(nodes, Config),

    %% master starts the dealer
    N = length(Nodes),
    F = (N div 3),
    ct:pal("N is ~p, F is ~p", [N, F]),
    BatchSize = 20,
    {ok, Dealer} = dealer:new(N, F+1, 'SS512'),
    {ok, {PubKey, PrivateKeys}} = dealer:deal(Dealer),

    %% each node gets a secret key
    NodesSKs = lists:zip(Nodes, PrivateKeys),

    %% load hbbft_worker on each node
    {Mod, Bin, _} = code:get_object_code(hbbft_worker),
    _ = hbbft_ct_utils:pmap(fun(Node) ->
                                    rpc:call(Node, erlang, load_module, [Mod, Bin])
                            end, Nodes),

    %% partition the first node from f other nodes
    FirstNode = hd(Nodes),
    PartitionedNodes = lists:sublist(Nodes, 2, F),
    [ true = ct_rpc:call(FirstNode, erlang, set_cookie, [PartitionedNode, canttouchthis]) || PartitionedNode <- PartitionedNodes ],
    [ ct_rpc:call(FirstNode, erlang, disconnect_node, [PartitionedNode]) || PartitionedNode <- PartitionedNodes ],
    true = lists:all(fun(E) -> E == pang end, [ ct_rpc:call(FirstNode, net_adm, ping, [PartitionedNode]) || PartitionedNode <- PartitionedNodes]),
    true = lists:all(fun(E) -> E == pang end, [ ct_rpc:call(PartitionedNode, net_adm, ping, [FirstNode]) || PartitionedNode <- PartitionedNodes]),
    ct:pal("Partitioning ~p from ~p", [FirstNode, PartitionedNodes]),

    OtherNodes = Nodes -- [FirstNode | PartitionedNodes],

    %% start a hbbft_worker on each node
    Workers = [{Node, rpc:call(Node, hbbft_worker, start_link, [N, F, I, tpke_privkey:serialize(SK), BatchSize, false])} || {I, {Node, SK}} <- enumerate(NodesSKs)],
    ok = global:sync(),

    case Filter of
        undefined ->
            ok;
        _ ->
            [ hbbft_worker:set_filter(Filter, Worker) || {Node, {ok, Worker}} <- Workers, lists:member(Node, OtherNodes) ]
    end,

    [ link(W) || {_, {ok, W}} <- Workers ],

    %% bunch of msgs
    Msgs = [ crypto:strong_rand_bytes(128) || _ <- lists:seq(1, N*20)],

    %% feed the nodes some msgs
    lists:foreach(fun(Msg) ->
                          Destinations = random_n(rand:uniform(N), Workers),
                          ct:pal("destinations ~p~n", [Destinations]),
                          [hbbft_worker:submit_transaction(Msg, Destination) || {_Node, {ok, Destination}} <- Destinations]
                  end, Msgs),

    %% wait for all the worker's mailboxes to settle and.
    %% wait for the chains to converge
    Done = hbbft_ct_utils:wait_until(fun() ->
                                           Chains = lists:map(fun({_Node, {ok, W}}) ->
                                                                      {ok, Blocks} = hbbft_worker:get_blocks(W),
                                                                      Blocks
                                                              end, Workers),

                                           %% check we actually converged and made a chain
                                           lists:all(fun(C) -> length(C) > 1 end, Chains)
                                   end, 60*2, 500),

    AllChains = lists:map(fun({_Node, {ok, W}}) ->
                               {ok, Blocks} = hbbft_worker:get_blocks(W),
                               Blocks
                       end, Workers),
    %% find the shortest chain and check all chains have the same common prefix
    ShortestChainLen = hd(lists:sort([ length(C) || C <- AllChains ])),

    Chains = sets:from_list(lists:map(fun(C) -> lists:reverse(lists:sublist(lists:reverse(C), ShortestChainLen)) end, AllChains)),

    ct:pal("~p distinct chains~n", [sets:size(Chains)]),
    ct:pal("chain lengths ~p ~n", [[length(C) || C <- sets:to_list(Chains)]]),
    case Done of
        ok -> ok;
        _ ->
            lists:foreach(fun({_Node, {ok, W}}) ->
                                  Status = hbbft_worker:status(W),
                                  ct:pal("Status for ~p is ~p", [_Node, Status])
                          end, Workers),

            ct:fail("error")
    end,

    lists:foreach(fun(Chain) ->
                          %ct:pal("Chain: ~p~n", [Chain]),
                          ct:pal("chain is of height ~p~n", [length(Chain)]),

                          %% verify they are cryptographically linked,
                          true = hbbft_worker:verify_chain(Chain, PubKey),

                          %% check all transactions are unique
                          BlockTxns = lists:flatten([ hbbft_worker:block_transactions(B) || B <- Chain ]),
                          true = length(BlockTxns) == sets:size(sets:from_list(BlockTxns)),

                          %% check they're all members of the original message list
                          true = sets:is_subset(sets:from_list(BlockTxns), sets:from_list(Msgs)),
                          ct:pal("chain contains ~p distinct transactions~n", [length(BlockTxns)])
                  end, sets:to_list(Chains)),

    [ unlink(W) || {_, {ok, W}} <- Workers ],
    ok.



%% helpers
enumerate(List) ->
    lists:zip(lists:seq(0, length(List) - 1), List).

random_n(N, List) ->
    lists:sublist(shuffle(List), N).

shuffle(List) ->
    [X || {_,X} <- lists:sort([{rand:uniform(), N} || N <- List])].
