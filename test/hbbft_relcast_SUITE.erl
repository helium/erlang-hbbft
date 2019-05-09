-module(hbbft_relcast_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

-export([all/0, init_per_testcase/2, end_per_testcase/2]).
-export([
         init_test/1,
         one_actor_no_txns_test/1,
         two_actors_no_txns_test/1,
         one_actor_missing_test/1,
         two_actors_missing_test/1,
         start_on_demand_test/1
        ]).

all() ->
    [
     init_test,
     one_actor_no_txns_test,
     two_actors_no_txns_test,
     one_actor_missing_test,
     two_actors_missing_test,
     start_on_demand_test
    ].

init_per_testcase(TestCase, Config) ->
    N = 7,
    F = N div 4,
    Module = hbbft,
    BatchSize = 20,
    {ok, Dealer} = dealer:new(N, F+1, 'SS512'),
    {ok, {PubKey, PrivateKeys}} = dealer:deal(Dealer),
    ECCKeys = [ public_key:generate_key({namedCurve,?secp256r1}) || _ <- lists:seq(1, N)],

    [{n, N},
     {f, F},
     {batchsize, BatchSize},
     {module, Module},
     {pubkey, PubKey},
     {privatekeys, PrivateKeys},
     {ecckeys, ECCKeys},
     {data_dir, atom_to_list(TestCase)++"data"} | Config].

end_per_testcase(_, _Config) ->
    ok.

init_test(Config) ->
    PubKey = proplists:get_value(pubkey, Config),
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config),
    DataDir = proplists:get_value(data_dir, Config),
    BatchSize = proplists:get_value(batchsize, Config),

    PrivateKeys = proplists:get_value(privatekeys, Config),

    Workers = lists:foldl(fun({I, SK}, Acc) ->
                                  {ok, W} = hbbft_relcast_worker:start_link([
                                                                     {id, I},
                                                                     {sk, tpke_privkey:serialize(SK)},
                                                                     {n, N},
                                                                     {f, F},
                                                                     {data_dir, DataDir},
                                                                     {key_params, mk_key_params(I-1, proplists:get_value(ecckeys, Config))},
                                                                     {batchsize, BatchSize}
                                                                    ]),
                                  [W | Acc]
                          end, [], hbbft_test_utils:enumerate(PrivateKeys)),

    ct:pal("Workers: ~p", [Workers]),

    Msgs = [ crypto:strong_rand_bytes(128) || _ <- lists:seq(1, N*20)],
    %% feed the badgers some msgs
    lists:foreach(fun(Msg) ->
                          Destinations = hbbft_test_utils:random_n(rand:uniform(N), Workers),
                          [ok = hbbft_relcast_worker:submit_transaction(Msg, D) || D <- Destinations]
                  end, Msgs),

    %% wait for all the worker's mailboxes to settle and
    %% wait for the chains to converge
    ok = hbbft_ct_utils:wait_until(fun() ->
                                           Chains = sets:from_list(lists:map(fun(W) ->
                                                                                     {ok, Blocks} = hbbft_relcast_worker:get_blocks(W),
                                                                                     Blocks
                                                                             end, Workers)),

                                           0 == lists:sum([element(2, erlang:process_info(W, message_queue_len)) || W <- Workers ]) andalso
                                           1 == sets:size(Chains) andalso
                                           0 /= length(hd(sets:to_list(Chains)))
                                   end, 60*2, 500),

    Chains = sets:from_list(lists:map(fun(W) ->
                                              {ok, Blocks} = hbbft_relcast_worker:get_blocks(W),
                                              Blocks
                                      end, Workers)),
    1 = sets:size(Chains),
    [Chain] = sets:to_list(Chains),
    ct:pal("chain is of height ~p~n", [length(Chain)]),
    %% verify they are cryptographically linked
    true = hbbft_relcast_worker:verify_chain(Chain, PubKey),
    %% check all the transactions are unique
    BlockTxns = lists:flatten([ hbbft_relcast_worker:block_transactions(B) || B <- Chain ]),
    true = length(BlockTxns) == sets:size(sets:from_list(BlockTxns)),
    %% check they're all members of the original message list
    true = sets:is_subset(sets:from_list(BlockTxns), sets:from_list(Msgs)),
    ct:pal("chain contains ~p distinct transactions~n", [length(BlockTxns)]),
    [gen_server:stop(W) || W <- Workers],
    ok.

one_actor_no_txns_test(Config) ->
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config),
    BatchSize = proplists:get_value(batchsize, Config),
    Module = proplists:get_value(module, Config),
    PrivateKeys = proplists:get_value(privatekeys, Config),

    StatesWithIndex = [{J, hbbft:init(Sk, N, F, J, BatchSize, infinity)} || {J, Sk} <- lists:zip(lists:seq(0, N - 1), PrivateKeys)],
    Msgs = [ crypto:strong_rand_bytes(128) || _ <- lists:seq(1, N*10)],
    %% send each message to a random subset of the HBBFT actors
    {NewStates, Replies} = lists:foldl(fun(Msg, {States, Replies}) ->
                                               Destinations = hbbft_utils:random_n(rand:uniform(N-1), lists:sublist(States, N-1)),
                                               {NewStates, NewReplies} = lists:unzip(lists:map(fun({J, Data}) ->
                                                                                                       {NewData, Reply} = hbbft:input(Data, Msg),
                                                                                                       {{J, NewData}, {J, Reply}}
                                                                                               end, lists:keysort(1, Destinations))),
                                               {lists:ukeymerge(1, NewStates, States), hbbft_test_utils:merge_replies(N, NewReplies, Replies)}
                                       end, {StatesWithIndex, []}, Msgs),
    %% check that at least N-F actors have started ACS:
    ?assert(length(Replies) >= N - F),
    %% all the nodes that have started ACS should have tried to send messages to all N peers (including themselves)
    ?assert(lists:all(fun(E) -> E end, [ length(R) == N || {_, {send, R}} <- Replies ])),
    %% start it on runnin'
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(Module, Replies, NewStates, sets:new()),
    %% check all N actors returned a result
    ?assertEqual(N, sets:size(ConvergedResults)),
    DistinctResults = sets:from_list([BVal || {result, {_, BVal}} <- sets:to_list(ConvergedResults)]),
    %% check all N actors returned the same result
    ?assertEqual(1, sets:size(DistinctResults)),
    {_, _, AcceptedMsgs} = lists:unzip3(lists:flatten(sets:to_list(DistinctResults))),
    %% check all the Msgs are actually from the original set
    ?assert(sets:is_subset(sets:from_list(lists:flatten(AcceptedMsgs)), sets:from_list(Msgs))),
    ok.

two_actors_no_txns_test(Config) ->
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config),
    BatchSize = proplists:get_value(batchsize, Config),
    Module = proplists:get_value(module, Config),
    PrivateKeys = proplists:get_value(privatekeys, Config),

    StatesWithIndex = [{J, hbbft:init(Sk, N, F, J, BatchSize, infinity)} || {J, Sk} <- lists:zip(lists:seq(0, N - 1), PrivateKeys)],
    Msgs = [ crypto:strong_rand_bytes(128) || _ <- lists:seq(1, N*10)],
    %% send each message to a random subset of the HBBFT actors
    {NewStates, Replies} = lists:foldl(fun(Msg, {States, Replies}) ->
                                               Destinations = hbbft_utils:random_n(rand:uniform(N-2), lists:sublist(States, N-2)),
                                               {NewStates, NewReplies} = lists:unzip(lists:map(fun({J, Data}) ->
                                                                                                       {NewData, Reply} = hbbft:input(Data, Msg),
                                                                                                       {{J, NewData}, {J, Reply}}
                                                                                               end, lists:keysort(1, Destinations))),
                                               {lists:ukeymerge(1, NewStates, States), hbbft_test_utils:merge_replies(N, NewReplies, Replies)}
                                       end, {StatesWithIndex, []}, Msgs),
    %% check that at least N-F actors have started ACS:
    ?assert(length(Replies) =< N - F),
    %% all the nodes that have started ACS should have tried to send messages to all N peers (including themselves)
    ?assert(lists:all(fun(E) -> E end, [ length(R) == N || {_, {send, R}} <- Replies ])),
    %% start it on runnin'
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(Module, Replies, NewStates, sets:new()),
    %% check no actors returned a result
    ?assertEqual(0, sets:size(ConvergedResults)),
    ok.

one_actor_missing_test(Config) ->
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config),
    BatchSize = proplists:get_value(batchsize, Config),
    Module = proplists:get_value(module, Config),
    PrivateKeys = proplists:get_value(privatekeys, Config),

    StatesWithIndex = [{J, hbbft:init(Sk, N, F, J, BatchSize, infinity)} || {J, Sk} <- lists:zip(lists:seq(0, N - 2), lists:sublist(PrivateKeys, N-1))],
    Msgs = [ crypto:strong_rand_bytes(128) || _ <- lists:seq(1, N*10)],
    %% send each message to a random subset of the HBBFT actors
    {NewStates, Replies} = lists:foldl(fun(Msg, {States, Replies}) ->
                                               Destinations = hbbft_utils:random_n(rand:uniform(N-1), States),
                                               {NewStates, NewReplies} = lists:unzip(lists:map(fun({J, Data}) ->
                                                                                                       {NewData, Reply} = hbbft:input(Data, Msg),
                                                                                                       {{J, NewData}, {J, Reply}}
                                                                                               end, lists:keysort(1, Destinations))),
                                               {lists:ukeymerge(1, NewStates, States), hbbft_test_utils:merge_replies(N, NewReplies, Replies)}
                                       end, {StatesWithIndex, []}, Msgs),
    %% check that at least N-F actors have started ACS:
    ?assert(length(Replies) >= N - F),
    %% all the nodes that have started ACS should have tried to send messages to all N peers (including themselves)
    ?assert(lists:all(fun(E) -> E end, [ length(R) == N || {_, {send, R}} <- Replies ])),
    %% start it on runnin'
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(Module, Replies, NewStates, sets:new()),
    %% check no actors returned a result
    ?assertEqual(N - 1, sets:size(ConvergedResults)),
    DistinctResults = sets:from_list([BVal || {result, {_, BVal}} <- sets:to_list(ConvergedResults)]),
    %% check all N actors returned the same result
    ?assertEqual(1, sets:size(DistinctResults)),
    {_, _, AcceptedMsgs} = lists:unzip3(lists:flatten(sets:to_list(DistinctResults))),
    %% check all the Msgs are actually from the original set
    ?assert(sets:is_subset(sets:from_list(lists:flatten(AcceptedMsgs)), sets:from_list(Msgs))),
    ok.

two_actors_missing_test(Config) ->
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config),
    BatchSize = proplists:get_value(batchsize, Config),
    Module = proplists:get_value(module, Config),
    PrivateKeys = proplists:get_value(privatekeys, Config),

    StatesWithIndex = [{J, hbbft:init(Sk, N, F, J, BatchSize, infinity)} || {J, Sk} <- lists:zip(lists:seq(0, N - 3), lists:sublist(PrivateKeys, N-2))],
    Msgs = [ crypto:strong_rand_bytes(128) || _ <- lists:seq(1, N*10)],
    %% send each message to a random subset of the HBBFT actors
    {NewStates, Replies} = lists:foldl(fun(Msg, {States, Replies}) ->
                                               Destinations = hbbft_utils:random_n(rand:uniform(N-2), States),
                                               {NewStates, NewReplies} = lists:unzip(lists:map(fun({J, Data}) ->
                                                                                                       {NewData, Reply} = hbbft:input(Data, Msg),
                                                                                                       {{J, NewData}, {J, Reply}}
                                                                                               end, lists:keysort(1, Destinations))),
                                               {lists:ukeymerge(1, NewStates, States), hbbft_test_utils:merge_replies(N, NewReplies, Replies)}
                                       end, {StatesWithIndex, []}, Msgs),
    %% check that at least N-F actors have started ACS:
    ?assert(length(Replies) =< N - F),
    %% all the nodes that have started ACS should have tried to send messages to all N peers (including themselves)
    ?assert(lists:all(fun(E) -> E end, [ length(R) == N || {_, {send, R}} <- Replies ])),
    %% start it on runnin'
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(Module, Replies, NewStates, sets:new()),
    %% check no actors returned a result
    ?assertEqual(0, sets:size(ConvergedResults)),
    ok.

start_on_demand_test(Config) ->
    PubKey = proplists:get_value(pubkey, Config),
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config),
    DataDir = proplists:get_value(data_dir, Config),
    BatchSize = proplists:get_value(batchsize, Config),

    PrivateKeys = proplists:get_value(privatekeys, Config),

    Workers = lists:foldl(fun({I, SK}, Acc) ->
                                  {ok, W} = hbbft_relcast_worker:start_link([
                                                                     {id, I},
                                                                     {sk, tpke_privkey:serialize(SK)},
                                                                     {n, N},
                                                                     {f, F},
                                                                     {data_dir, DataDir},
                                                                     {key_params, mk_key_params(I-1, proplists:get_value(ecckeys, Config))},
                                                                     {batchsize, BatchSize}
                                                                    ]),
                                  [W | Acc]
                          end, [], hbbft_test_utils:enumerate(PrivateKeys)),


    [W1, _W2 | RemainingWorkers] = Workers,

    Msgs = [ crypto:strong_rand_bytes(128) || _ <- lists:seq(1, N*20)],

    KnownMsg = crypto:strong_rand_bytes(128),

    %% feed the badgers some msgs
    lists:foreach(fun(Msg) ->
                          Destinations = hbbft_test_utils:random_n(rand:uniform(length(RemainingWorkers)), RemainingWorkers),
                          io:format("destinations ~p~n", [Destinations]),
                          [ok = hbbft_relcast_worker:submit_transaction(Msg, D) || D <- Destinations]
                  end, Msgs),

    ok = hbbft_relcast_worker:submit_transaction(KnownMsg, W1),

    _ = hbbft_relcast_worker:start_on_demand(W1),

    %% wait for all the worker's mailboxes to settle and
    %% wait for the chains to converge
    WaitRes = hbbft_ct_utils:wait_until(fun() ->
                                           Chains = sets:from_list(lists:map(fun(W) ->
                                                                                     {ok, Blocks} = hbbft_relcast_worker:get_blocks(W),
                                                                                     Blocks
                                                                             end, Workers)),

                                           0 == lists:sum([element(2, erlang:process_info(W, message_queue_len)) || W <- Workers ]) andalso
                                           1 == sets:size(Chains) andalso
                                           0 /= length(hd(sets:to_list(Chains)))
                                   end, 60*2, 500),
    case WaitRes of
        ok ->
            ok;
        _ ->
            [begin
                 {_State, Inbound, Outbound} = hbbft_relcast_worker:relcast_status(W),
                 ct:pal("~p Inbound : ~p", [W, [{K, binary_to_term(V)} || {K, V} <- Inbound]]),
                 ct:pal("~p Outbound : ~p", [W, maps:map(fun(_K, V) -> [binary_to_term(X) || X <- V] end, Outbound)])
             end || W <- Workers ],
             ok = WaitRes
    end,


    Chains = sets:from_list(lists:map(fun(W) ->
                                              {ok, Blocks} = hbbft_relcast_worker:get_blocks(W),
                                              Blocks
                                      end, Workers)),
    1 = sets:size(Chains),
    [Chain] = sets:to_list(Chains),
    io:format("chain is of height ~p~n", [length(Chain)]),
    %% verify they are cryptographically linked
    true = hbbft_relcast_worker:verify_chain(Chain, PubKey),
    %% check all the transactions are unique
    BlockTxns = lists:flatten([ hbbft_relcast_worker:block_transactions(B) || B <- Chain ]),
    true = lists:member(KnownMsg, BlockTxns),
    true = length(BlockTxns) == sets:size(sets:from_list(BlockTxns)),
    %% check they're all members of the original message list
    true = sets:is_subset(sets:from_list(BlockTxns), sets:from_list([KnownMsg | Msgs])),
    io:format("chain contains ~p distinct transactions~n", [length(BlockTxns)]),
    [gen_server:stop(W) || W <- Workers],
    ok.


mk_key_params(I, Keylist) ->
    ct:pal("I ~p~n", [I]),
    PrivKey = lists:nth(I+1, Keylist),
    PubKeys = lists:map(fun(#'ECPrivateKey'{parameters=_Params, publicKey=PubKey}) ->     {#'ECPoint'{point = PubKey}, _Params} end, Keylist),
    {PubKeys, fun(Bin) -> public_key:sign(Bin, sha256, PrivKey) end, fun({PubKey, {namedCurve, ?secp256r1}}) -> public_key:compute_key(PubKey, PrivKey) end}.
