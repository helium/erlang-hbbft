-module(hbbft_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-include_lib("relcast/include/fakecast.hrl").

-export([all/0, groups/0, init_per_group/2, end_per_group/2, init_per_testcase/2, end_per_testcase/2]).
-export([
    init_test/1,
    one_actor_no_txns_test/1,
    two_actors_no_txns_test/1,
    one_actor_missing_test/1,
    two_actors_missing_test/1,
    encrypt_decrypt_test/1,
    start_on_demand_test/1,
    one_actor_wrong_key_test/1,
    one_actor_corrupted_key_test/1,
    one_actor_oversized_batch_test/1,
    batch_size_limit_minimal_test/1,
    initial_fakecast_test/1
]).

all() ->
    [{group, bls12_381}].

test_cases() ->
    [
        init_test,
        one_actor_no_txns_test,
        two_actors_no_txns_test,
        one_actor_missing_test,
        two_actors_missing_test,
        encrypt_decrypt_test,
        start_on_demand_test,
        one_actor_wrong_key_test,
        one_actor_corrupted_key_test,
        one_actor_oversized_batch_test,
        batch_size_limit_minimal_test,
        initial_fakecast_test
    ].

groups() ->
    [{bls12_381, [], test_cases()}].

init_per_group(bls12_381, Config) ->
    [{curve, 'BLS12-381'} | Config].

end_per_group(_, _Config) ->
    ok.

init_per_testcase(_, Config) ->
    N = 4,
    F = N div 4,
    Module = hbbft,
    BatchSize = 20,
    PrivateKeys = tc_key_share:deal(N, F),
    [{n, N}, {f, F}, {batchsize, BatchSize}, {module, Module}, {privatekeys, PrivateKeys} | Config].

end_per_testcase(_, _Config) ->
    ok.

init_test(Config) ->
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config),
    Curve = proplists:get_value(curve, Config),
    BatchSize = proplists:get_value(batchsize, Config),
    PrivateKeys = proplists:get_value(privatekeys, Config),
    ct:pal("privkeys ~p", [PrivateKeys]),
    Workers = [
        element(2, hbbft_worker:start_link(N, F, I, hbbft_test_utils:serialize_key(Curve, SK), BatchSize, false))
     || {I, SK} <- enumerate(PrivateKeys)
    ],
    Msgs = [crypto:strong_rand_bytes(128) || _ <- lists:seq(1, N * 20)],
    %% feed the badgers some msgs
    lists:foreach(
        fun(Msg) ->
            Destinations = random_n(rand:uniform(N), Workers),
            ct:log("destinations ~p~n", [Destinations]),
            [ok = hbbft_worker:submit_transaction(Msg, D) || D <- Destinations]
        end,
        Msgs
    ),

    %% wait for all the worker's mailboxes to settle and
    %% wait for the chains to converge
    ok = wait_for_chains(Workers, 2),

    Chains = get_common_chain(Workers),

    1 = sets:size(Chains),
    [Chain] = sets:to_list(Chains),
    ct:log("chain is of height ~p~n", [length(Chain)]),
    %% verify they are cryptographically linked
    true = hbbft_worker:verify_chain(Chain, hd(PrivateKeys)),
    %% check all the transactions are unique
    BlockTxns = lists:flatten([hbbft_worker:block_transactions(B) || B <- Chain]),
    true = length(BlockTxns) == sets:size(sets:from_list(BlockTxns)),
    %% check they're all members of the original message list
    true = sets:is_subset(sets:from_list(BlockTxns), sets:from_list(Msgs)),
    ct:log("chain contains ~p distinct transactions~n", [length(BlockTxns)]),
    ok.

one_actor_no_txns_test(Config) ->
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config),
    BatchSize = proplists:get_value(batchsize, Config),
    Module = proplists:get_value(module, Config),
    PrivateKeys = proplists:get_value(privatekeys, Config),

    StatesWithIndex = [
        {J, hbbft:init(Sk, N, F, J, BatchSize, infinity)}
     || {J, Sk} <- lists:zip(lists:seq(0, N - 1), PrivateKeys)
    ],
    Msgs = [crypto:strong_rand_bytes(128) || _ <- lists:seq(1, N * 10)],
    %% send each message to a random subset of the HBBFT actors
    {NewStates, Replies} = lists:foldl(
        fun(Msg, {States, Replies}) ->
            Destinations = hbbft_utils:random_n(rand:uniform(N - 1), lists:sublist(States, N - 1)),
            {NewStates, NewReplies} = lists:unzip(
                lists:map(
                    fun({J, Data}) ->
                        {NewData, Reply} = hbbft:input(Data, Msg),
                        {{J, NewData}, {J, Reply}}
                    end,
                    lists:keysort(1, Destinations)
                )
            ),
            {lists:ukeymerge(1, NewStates, States), merge_replies(N, NewReplies, Replies)}
        end,
        {StatesWithIndex, []},
        Msgs
    ),
    %% check that at least N-F actors have started ACS:
    ?assert(length(Replies) >= N - F),
    %% all the nodes that have started ACS should have tried to send messages to all N peers (including themselves)
    ?assert(lists:all(fun(E) -> E end, [length(R) == N || {_, {send, R}} <- Replies])),
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

    StatesWithIndex = [
        {J, hbbft:init(Sk, N, F, J, BatchSize, infinity)}
     || {J, Sk} <- lists:zip(lists:seq(0, N - 1), PrivateKeys)
    ],
    Msgs = [crypto:strong_rand_bytes(128) || _ <- lists:seq(1, N * 10)],
    %% send each message to a random subset of the HBBFT actors
    {NewStates, Replies} = lists:foldl(
        fun(Msg, {States, Replies}) ->
            Destinations = hbbft_utils:random_n(rand:uniform(N - 2), lists:sublist(States, N - 2)),
            {NewStates, NewReplies} = lists:unzip(
                lists:map(
                    fun({J, Data}) ->
                        {NewData, Reply} = hbbft:input(Data, Msg),
                        {{J, NewData}, {J, Reply}}
                    end,
                    lists:keysort(1, Destinations)
                )
            ),
            {lists:ukeymerge(1, NewStates, States), merge_replies(N, NewReplies, Replies)}
        end,
        {StatesWithIndex, []},
        Msgs
    ),
    %% check that at least N-F actors have started ACS:
    ?assert(length(Replies) =< N - F),
    %% all the nodes that have started ACS should have tried to send messages to all N peers (including themselves)
    ?assert(lists:all(fun(E) -> E end, [length(R) == N || {_, {send, R}} <- Replies])),
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

    StatesWithIndex = [
        {J, hbbft:init(Sk, N, F, J, BatchSize, infinity)}
     || {J, Sk} <- lists:zip(lists:seq(0, N - 2), lists:sublist(PrivateKeys, N - 1))
    ],
    Msgs = [crypto:strong_rand_bytes(128) || _ <- lists:seq(1, N * 10)],
    %% send each message to a random subset of the HBBFT actors
    {NewStates, Replies} = lists:foldl(
        fun(Msg, {States, Replies}) ->
            Destinations = hbbft_utils:random_n(rand:uniform(N - 1), States),
            {NewStates, NewReplies} = lists:unzip(
                lists:map(
                    fun({J, Data}) ->
                        {NewData, Reply} = hbbft:input(Data, Msg),
                        {{J, NewData}, {J, Reply}}
                    end,
                    lists:keysort(1, Destinations)
                )
            ),
            {lists:ukeymerge(1, NewStates, States), merge_replies(N, NewReplies, Replies)}
        end,
        {StatesWithIndex, []},
        Msgs
    ),
    %% check that at least N-F actors have started ACS:
    ?assert(length(Replies) >= N - F),
    %% all the nodes that have started ACS should have tried to send messages to all N peers (including themselves)
    ?assert(lists:all(fun(E) -> E end, [length(R) == N || {_, {send, R}} <- Replies])),
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

    StatesWithIndex = [
        {J, hbbft:init(Sk, N, F, J, BatchSize, infinity)}
     || {J, Sk} <- lists:zip(lists:seq(0, N - 3), lists:sublist(PrivateKeys, N - 2))
    ],
    Msgs = [crypto:strong_rand_bytes(128) || _ <- lists:seq(1, N * 10)],
    %% send each message to a random subset of the HBBFT actors
    {NewStates, Replies} = lists:foldl(
        fun(Msg, {States, Replies}) ->
            Destinations = hbbft_utils:random_n(rand:uniform(N - 2), States),
            {NewStates, NewReplies} = lists:unzip(
                lists:map(
                    fun({J, Data}) ->
                        {NewData, Reply} = hbbft:input(Data, Msg),
                        {{J, NewData}, {J, Reply}}
                    end,
                    lists:keysort(1, Destinations)
                )
            ),
            {lists:ukeymerge(1, NewStates, States), merge_replies(N, NewReplies, Replies)}
        end,
        {StatesWithIndex, []},
        Msgs
    ),
    %% check that at least N-F actors have started ACS:
    ?assert(length(Replies) =< N - F),
    %% all the nodes that have started ACS should have tried to send messages to all N peers (including themselves)
    ?assert(lists:all(fun(E) -> E end, [length(R) == N || {_, {send, R}} <- Replies])),
    %% start it on runnin'
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(Module, Replies, NewStates, sets:new()),
    %% check no actors returned a result
    ?assertEqual(0, sets:size(ConvergedResults)),
    ok.

encrypt_decrypt_test(Config) ->
    PrivateKeys = [SK1 | _RemainingSKs] = proplists:get_value(privatekeys, Config),
    PlainText = crypto:strong_rand_bytes(24),
    Ciphertext = tc_ciphertext:deserialize(hbbft:encrypt('BLS12-381', hd(PrivateKeys), PlainText)),
    DecShares = [tc_key_share:decrypt_share(SK, Ciphertext) || SK <- PrivateKeys],
    {ok, Decrypted} = tc_key_share:combine_decryption_shares(SK1, DecShares, Ciphertext),
    ?assertEqual(PlainText, Decrypted),
    ok.

start_on_demand_test(Config) ->
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config),
    Curve = proplists:get_value(curve, Config),
    BatchSize = proplists:get_value(batchsize, Config),
    PrivateKeys = proplists:get_value(privatekeys, Config),
    Workers = [
        element(2, hbbft_worker:start_link(N, F, I, hbbft_test_utils:serialize_key(Curve, SK), BatchSize, false))
     || {I, SK} <- enumerate(PrivateKeys)
    ],

    [W1, _W2 | RemainingWorkers] = Workers,

    Msgs = [crypto:strong_rand_bytes(128) || _ <- lists:seq(1, N * 20)],

    KnownMsg = crypto:strong_rand_bytes(128),
    %% feed the badgers some msgs
    lists:foreach(
        fun(Msg) ->
            Destinations = random_n(rand:uniform(length(RemainingWorkers)), RemainingWorkers),
            ct:log("destinations ~p~n", [Destinations]),
            [ok = hbbft_worker:submit_transaction(Msg, D) || D <- Destinations]
        end,
        Msgs
    ),

    ok = hbbft_worker:submit_transaction(KnownMsg, W1),

    _ = hbbft_worker:start_on_demand(W1),

    %% wait for all the worker's mailboxes to settle and
    %% wait for the chains to converge
    ok = wait_for_chains(Workers, 1),

    Chains = get_common_chain(Workers),

    1 = sets:size(Chains),
    [Chain] = sets:to_list(Chains),
    ct:log("chain is of height ~p~n", [length(Chain)]),
    %% verify they are cryptographically linked
    true = hbbft_worker:verify_chain(Chain, hd(PrivateKeys)),
    %% check all the transactions are unique
    BlockTxns = lists:flatten([hbbft_worker:block_transactions(B) || B <- Chain]),
    true = lists:member(KnownMsg, BlockTxns),
    true = length(BlockTxns) == sets:size(sets:from_list(BlockTxns)),
    %% check they're all members of the original message list
    true = sets:is_subset(sets:from_list(BlockTxns), sets:from_list([KnownMsg | Msgs])),
    ct:log("chain contains ~p distinct transactions~n", [length(BlockTxns)]),
    ok.

one_actor_wrong_key_test(Config) ->
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config),
    Curve = proplists:get_value(curve, Config),
    BatchSize = proplists:get_value(batchsize, Config),
    PrivateKeys0 = proplists:get_value(privatekeys, Config),
    PrivateKeys1 = tc_key_share:deal(N, F),
    %% give actor 1 a completely unrelated key
    %% this will prevent it from doing any valid threshold cryptography
    %% and thus it will not be able to reach consensus
    PrivateKeys = [hd(PrivateKeys1) | tl(PrivateKeys0)],

    Workers = [
        element(2, hbbft_worker:start_link(N, F, I, hbbft_test_utils:serialize_key(Curve, SK), BatchSize, false))
     || {I, SK} <- enumerate(PrivateKeys)
    ],
    Msgs = [crypto:strong_rand_bytes(128) || _ <- lists:seq(1, N * 20)],
    %% feed the badgers some msgs
    lists:foreach(
        fun(Msg) ->
            Destinations = random_n(rand:uniform(N), Workers),
            ct:log("destinations ~p~n", [Destinations]),
            [ok = hbbft_worker:submit_transaction(Msg, D) || D <- Destinations]
        end,
        Msgs
    ),

    %% wait for all the worker's mailboxes to settle and
    %% wait for the chains to converge
    Result = wait_for_chains(Workers, 1),

    Chains = get_common_chain(Workers),

    ct:pal("Chains ~p", [sets:to_list(Chains)]),

    1 = sets:size(Chains),
    [Chain] = sets:to_list(Chains),
    ct:log("chain is of height ~p~n", [length(Chain)]),
    %% verify they are cryptographically linked
    true = hbbft_worker:verify_chain(lists:reverse(Chain), hd(PrivateKeys0)),
    %% check all the transactions are unique
    BlockTxns = lists:flatten([hbbft_worker:block_transactions(B) || B <- Chain]),
    true = length(BlockTxns) == sets:size(sets:from_list(BlockTxns)),
    %% check they're all members of the original message list
    true = sets:is_subset(sets:from_list(BlockTxns), sets:from_list(Msgs)),
    ct:log("chain contains ~p distinct transactions~n", [length(BlockTxns)]),
    ok = Result,
    ok.

one_actor_corrupted_key_test(Config) ->
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config),
    Curve = proplists:get_value(curve, Config),
    BatchSize = proplists:get_value(batchsize, Config),
    [PK1 | PrivateKeys0] = proplists:get_value(privatekeys, Config),
    %% scramble the index of the key
    %% this will not prevent the actor for encrypting their bundle
    %% merely prevent it producing valid decryption shares
    %% thus all the actors will be able to converge
    Pos = 4,
    PK2 = setelement(Pos, PK1, element(Pos, PK1) + 1000),
    PrivateKeys = [PK2 | PrivateKeys0],

    Workers = [
        element(2, hbbft_worker:start_link(N, F, I, hbbft_test_utils:serialize_key(Curve, SK), BatchSize, false))
     || {I, SK} <- enumerate(PrivateKeys)
    ],
    Msgs = [crypto:strong_rand_bytes(128) || _ <- lists:seq(1, N * 20)],
    %% feed the badgers some msgs
    lists:foreach(
        fun(Msg) ->
            Destinations = random_n(rand:uniform(N), Workers),
            ct:log("destinations ~p~n", [Destinations]),
            [ok = hbbft_worker:submit_transaction(Msg, D) || D <- Destinations]
        end,
        Msgs
    ),

    %% wait for all the worker's mailboxes to settle and
    %% wait for the chains to converge
    ok = wait_for_chains(Workers, 2),

    Chains = get_common_chain(Workers),

    1 = sets:size(Chains),
    [Chain] = sets:to_list(Chains),
    ct:log("chain is of height ~p~n", [length(Chain)]),
    %% verify they are cryptographically linked
    true = hbbft_worker:verify_chain(Chain, hd(PrivateKeys)),
    %% check all the transactions are unique
    BlockTxns = lists:flatten([hbbft_worker:block_transactions(B) || B <- Chain]),
    true = length(BlockTxns) == sets:size(sets:from_list(BlockTxns)),
    %% check they're all members of the original message list
    true = sets:is_subset(sets:from_list(BlockTxns), sets:from_list(Msgs)),
    ct:log("chain contains ~p distinct transactions~n", [length(BlockTxns)]),
    ok.

one_actor_oversized_batch_test(Config) ->
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config),
    Curve = proplists:get_value(curve, Config),
    B = proplists:get_value(batchsize, Config),
    PrivateKeys = [SK1 | SKs] = proplists:get_value(privatekeys, Config),

    % with an oversized batch parameter
    BadWorker =
        ok(hbbft_worker:start_link(N, F, 0, hbbft_test_utils:serialize_key(Curve, SK1), B + 1, false)),
    GoodWorkers =
        [
            ok(hbbft_worker:start_link(N, F, I + 1, hbbft_test_utils:serialize_key(Curve, SKi), B, false))
         || {I, SKi} <- enumerate(SKs)
        ],

    % Each node needs at least B/N transactions.
    GoodTxns = [list_to_binary("GOOD_" ++ integer_to_list(I)) || I <- lists:seq(1, B * N)],
    BadTxns = [list_to_binary("BAD_" ++ integer_to_list(I)) || I <- lists:seq(1, B)],

    % Submit transactions:
    lists:foreach(
        fun(T) -> ok = hbbft_worker:submit_transaction(T, BadWorker) end,
        BadTxns
    ),
    lists:foreach(
        fun(T) ->
            Destinations = random_n(rand:uniform(N), GoodWorkers),
            [ok = hbbft_worker:submit_transaction(T, D) || D <- Destinations]
        end,
        GoodTxns
    ),

    % Wait for all the worker's mailboxes to settle:
    ok = wait_for_chains([BadWorker | GoodWorkers], 2),

    % Wait for the chains to converge:
    Chains = get_common_chain(GoodWorkers),
    1 = sets:size(Chains),
    [Chain] = sets:to_list(Chains),
    CommittedTxns =
        lists:flatten([hbbft_worker:block_transactions(Block) || Block <- Chain]),

    % Transactions are cryptographically linked:
    ?assertMatch(true, hbbft_worker:verify_chain(Chain, hd(PrivateKeys))),

    % Transactions are unique:
    ?assertMatch([], CommittedTxns -- lists:usort(CommittedTxns)),

    % Finally, quod erat demonstrandum - that
    % only the expected transactions were committed:
    ?assertMatch([], CommittedTxns -- GoodTxns),
    ok.

batch_size_limit_minimal_test(Config) ->
    % Same test goal as one_actor_oversized_batch_test, but
    % the absolute minimal to test the state transition.
    N = 1,
    F = 0,
    Curve = proplists:get_value(curve, Config),
    BatchSize = 1,
    [SK | _] = tc_key_share:deal(N, F),

    % Protocol begins.
    ProtocolInstanceId = 0,
    State_0 = hbbft:init(SK, N, F, ProtocolInstanceId, BatchSize, infinity),

    % Transactions submitted. One more than max batch size.
    Buf = [list_to_binary(integer_to_list(Txn)) || Txn <- lists:seq(1, BatchSize + 1)],

    % Pretending ACS happened here.
    Stamp = <<"trust-me-im-a-stamp">>,
    Enc = tc_pubkey:encrypt(tc_key_share:public_key(SK), hbbft:encode_list([Stamp | Buf])),

    % E?
    AcsInstanceId = 0,
    State_1 = hbbft:abstraction_breaking_set_acs_results(State_0, [{AcsInstanceId, Enc}]),
    State_2 = hbbft:abstraction_breaking_set_enc_keys(State_1, #{AcsInstanceId => Enc}),

    % Decoding transactions from ACS, which we expect to be rejectected.
    {State_3, Result} =
        hbbft:handle_msg(
            State_2,
            ProtocolInstanceId,
            {
                dec,
                hbbft:round(State_2),
                AcsInstanceId,
                hbbft_utils:dec_share_to_binary(Curve, tc_key_share:decrypt_share(SK, Enc))
            }
        ),
    ?assertMatch({result, {transactions, [], []}}, Result),
    ?assertMatch(#{sent_txns := true}, hbbft:status(State_3)),
    ok.

-record(state, {
    node_count :: integer(),
    stopped = false :: boolean(),
    results = sets:new() :: sets:set()
}).

trivial(
    _Message,
    _From,
    _To,
    _NodeState,
    _NewState,
    _Actions,
    #state{stopped = false} = State
) ->
    case rand:uniform(100) of
        100 ->
            {actions, [{stop_node, 2}], State#state{stopped = true}};
        _ ->
            {actions, [], State}
    end;
trivial(
    _Message,
    _From,
    To,
    _NodeState,
    _NewState,
    {result, Result},
    #state{results = Results0} = State
) ->
    Results = sets:add_element({result, {To, Result}}, Results0),
    %% ct:pal("results len ~p ~p", [sets:size(Results), sets:to_list(Results)]),
    case sets:size(Results) == State#state.node_count of
        true ->
            {result, Results};
        false ->
            {actions, [], State#state{results = Results}}
    end;
trivial(_Message, _From, _To, _NodeState, _NewState, _Actions, ModelState) ->
    {actions, [], ModelState}.

initial_fakecast_test(Config) ->
    % proplists:get_value(n, Config),
    N = 4,
    % proplists:get_value(f, Config),
    F = 1,
    BatchSize = proplists:get_value(batchsize, Config),
    Module = proplists:get_value(module, Config),
    PrivateKeys0 = proplists:get_value(privatekeys, Config),
    {PrivateKeys, _} = lists:split(N, PrivateKeys0),

    Init = fun() ->
        {ok,
            #fc_conf{
                test_mod = Module,
                nodes = lists:seq(1, N),
                configs = [
                    [Sk, N, F, ID, BatchSize, infinity]
                 || {ID, Sk} <- lists:zip(lists:seq(0, N - 1), PrivateKeys)
                ]
            },
            #state{node_count = N - 2}}
    end,
    Msgs = [crypto:strong_rand_bytes(128) || _ <- lists:seq(1, N * 10)],
    %% send each message to a random subset of the HBBFT actors
    Input =
        fun() ->
            lists:foldl(
                fun(ID, Acc) ->
                    Size = max(length(Msgs), BatchSize + (rand:uniform(length(Msgs)))),
                    Subset = hbbft_test_utils:random_n(Size, Msgs),
                    lists:append([{ID, Msg} || Msg <- Subset], Acc)
                end,
                [],
                lists:seq(0, N - 1)
            )
        end,
    %% start it on runnin'
    {ok, ConvergedResults} = fakecast:start_test(
        Init,
        fun trivial/7,
        os:timestamp(),
        Input
    ),

    %% check all N actors returned a result
    ?assertEqual(N - 2, sets:size(ConvergedResults)),
    DistinctResults = sets:from_list([BVal || {result, {_, BVal}} <- sets:to_list(ConvergedResults)]),
    %% check all N actors returned the same result
    ?assertEqual(1, sets:size(DistinctResults)),
    {_, _, AcceptedMsgs} = lists:unzip3(lists:flatten(sets:to_list(DistinctResults))),
    %% check all the Msgs are actually from the original set
    ?assert(sets:is_subset(sets:from_list(lists:flatten(AcceptedMsgs)), sets:from_list(Msgs))),
    ok.

%% helper functions

ok({ok, X}) -> X.

enumerate(List) ->
    lists:zip(lists:seq(0, length(List) - 1), List).

random_n(N, List) ->
    lists:sublist(shuffle(List), N).

shuffle(List) ->
    [X || {_, X} <- lists:sort([{rand:uniform(), N} || N <- List])].

merge_replies(N, NewReplies, Replies) when N < 0 orelse length(NewReplies) == 0 ->
    Replies;
merge_replies(N, NewReplies, Replies) ->
    case lists:keyfind(N, 1, NewReplies) of
        false ->
            merge_replies(N - 1, lists:keydelete(N, 1, NewReplies), Replies);
        {N, ok} ->
            merge_replies(N - 1, lists:keydelete(N, 1, NewReplies), Replies);
        {N, {send, ToSend}} ->
            NewSend =
                case lists:keyfind(N, 1, Replies) of
                    false ->
                        {N, {send, ToSend}};
                    {N, OldSend} ->
                        {N, {send, OldSend ++ ToSend}}
                end,
            merge_replies(
                N - 1,
                lists:keydelete(N, 1, NewReplies),
                lists:keystore(N, 1, Replies, NewSend)
            )
    end.

wait_for_chains(Workers, MinHeight) ->
    hbbft_ct_utils:wait_until(
        fun() ->
            Chains = lists:map(
                fun(W) ->
                    {ok, Blocks} = hbbft_worker:get_blocks(W),
                    Blocks
                end,
                Workers
            ),

            lists:all(fun(C) -> length(C) >= MinHeight end, Chains)
        end,
        60 * 2,
        500
    ).

get_common_chain(Workers) ->
    AllChains = lists:map(
        fun(W) ->
            {ok, Blocks} = hbbft_worker:get_blocks(W),
            Blocks
        end,
        Workers
    ),
    %% find the shortest chain and check all chains have the same common prefix
    ShortestChainLen = hd(lists:sort([length(C) || C <- AllChains])),

    %% chains are stored in reverse, so we have to reverse them to get the first N blocks and then re-reverse them to restore expected ordering
    sets:from_list(
        lists:map(
            fun(C) -> lists:reverse(lists:sublist(lists:reverse(C), ShortestChainLen)) end,
            AllChains
        )
    ).
