-module(hbbft_rbc_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, init_per_testcase/2, end_per_testcase/2]).
-export([
         init_test/1,
         send_incorrect_msg_test/1,
         incorrect_leader_test/1,
         pid_dying_test/1,
         simple_test/1,
         two_pid_dying_test/1
        ]).

all() ->
    [
     init_test,
     send_incorrect_msg_test,
     incorrect_leader_test,
     pid_dying_test,
     simple_test,
     two_pid_dying_test
    ].

init_per_testcase(_, Config) ->
    N = 5,
    F = N div 4,
    Module = hbbft_rbc,
    Msg = crypto:strong_rand_bytes(512),
    [{n, N}, {f, F}, {module, Module}, {msg, Msg}| Config].

end_per_testcase(_, Config) ->
    Dealer = proplists:get_value(dealer, Config, undefined),
    case Dealer of
        undefined -> ok;
        Pid ->
            gen_server:stop(Pid)
    end.

init_test(Config) ->
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config),
    Module = proplists:get_value(module, Config),
    Msg = proplists:get_value(msg, Config),
    S0 = hbbft_rbc:init(N, F, 0, 0),
    S1 = hbbft_rbc:init(N, F, 1, 0),
    S2 = hbbft_rbc:init(N, F, 2, 0),
    S3 = hbbft_rbc:init(N, F, 3, 0),
    S4 = hbbft_rbc:init(N, F, 4, 0),
    {NewS0, {send, MsgsToSend}} = hbbft_rbc:input(S0, Msg),
    States = [NewS0, S1, S2, S3, S4],
    StatesWithId = lists:zip(lists:seq(0, length(States) - 1), States),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(Module, [{0, {send, MsgsToSend}}], StatesWithId, sets:new()),
    %% everyone should converge
    ?assertEqual(N, sets:size(ConvergedResults)),
    %% the decoded result should be the original message
    ConvergedResultsList = sets:to_list(ConvergedResults),
    ?assert(lists:all(fun({result, {_, Res}}) -> Res == Msg end, ConvergedResultsList)),
    ok.

send_incorrect_msg_test(Config) ->
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config),
    Module = proplists:get_value(module, Config),
    Msg = proplists:get_value(msg, Config),
    S0 = hbbft_rbc:init(N, F, 0, 0),
    S1 = hbbft_rbc:init(N, F, 1, 0),
    S2 = hbbft_rbc:init(N, F, 2, 0),
    S3 = hbbft_rbc:init(N, F, 3, 0),
    S4 = hbbft_rbc:init(N, F, 4, 0),
    {NewS0, {send, MsgsToSend}} = hbbft_rbc:input(S0, Msg),

    {unicast, _, {val, MerkleRootHash, _, _}} = hd(MsgsToSend),

    %% ====================================================
    %% screw up 3 val messages in the MsgsToSend
    %% TODO: something better but this works for now
    BadMsg = crypto:strong_rand_bytes(512),
    M = N - 2*F,
    K = 2*F,
    {ok, Shards} = leo_erasure:encode({K, M}, BadMsg),
    MsgSize = byte_size(BadMsg),
    ShardsWithSize = [{MsgSize, Shard} || Shard <- Shards],
    Merkle = merkerl:new(ShardsWithSize, fun merkerl:hash_value/1),
    BranchesForShards = [merkerl:gen_proof(Hash, Merkle) || {Hash, _} <- merkerl:leaves(Merkle)],
    BadMsgsToSend = [ {unicast, J, {val, MerkleRootHash, lists:nth(J+1, BranchesForShards), lists:nth(J+1, ShardsWithSize)}} || J <- lists:seq(0, N-1)],
    [ First, Second | _ ] = MsgsToSend,
    [ _, _, Third, Fourth, Fifth ] = BadMsgsToSend,
    NewMsgsToSend = [First, Second, Third, Fourth, Fifth],
    %% ====================================================

    States = [NewS0, S1, S2, S3, S4],
    StatesWithId = lists:zip(lists:seq(0, length(States) - 1), States),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(Module, [{0, {send, NewMsgsToSend}}], StatesWithId, sets:new()),
    ConvergedResultsList = sets:to_list(ConvergedResults),
    ?assert(lists:all(fun({result, {_, Res}}) -> Res == aborted end, ConvergedResultsList)),
    ?assertEqual(0, sets:size(ConvergedResults)),
    ok.

incorrect_leader_test(Config) ->
    %% RBC threshold is N - 2F
    %% ideally no one should converge
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config),
    Module = proplists:get_value(module, Config),
    Msg = proplists:get_value(msg, Config),
    S0 = hbbft_rbc:init(N, F, 0, 0),
    S1 = hbbft_rbc:init(N, F, 1, 0),
    S2 = hbbft_rbc:init(N, F, 2, 0),
    %% different leader than the one who proposed to start RBC
    S3 = hbbft_rbc:init(N, F, 3, 1),
    S4 = hbbft_rbc:init(N, F, 4, 1),
    {NewS0, {send, MsgsToSend}} = hbbft_rbc:input(S0, Msg),
    States = [NewS0, S1, S2, S3, S4],
    StatesWithId = lists:zip(lists:seq(0, length(States) - 1), States),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(Module, [{0, {send, MsgsToSend}}], StatesWithId, sets:new()),
    %% no one should converge
    ?assertEqual(0, sets:size(ConvergedResults)),
    ok.

pid_dying_test(Config) ->
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config),
    Module = proplists:get_value(module, Config),
    Msg = proplists:get_value(msg, Config),
    S0 = hbbft_rbc:init(N, F, 0, 0),
    S1 = hbbft_rbc:init(N, F, 1, 0),
    S3 = hbbft_rbc:init(N, F, 3, 0),
    S4 = hbbft_rbc:init(N, F, 4, 0),
    {NewS0, {send, MsgsToSend}} = hbbft_rbc:input(S0, Msg),
    States = [NewS0, S1, S3, S4],
    StatesWithId = lists:zip(lists:seq(0, length(States) - 1), States),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(Module, [{0, {send, MsgsToSend}}], StatesWithId, sets:new()),
    %% everyone but the dead node should converge
    ?assertEqual(N - 1, sets:size(ConvergedResults)),
    %% the decoded result should be the original message
    ConvergedResultsList = sets:to_list(ConvergedResults),
    ?assert(lists:all(fun({result, {_, Res}}) -> Res == Msg end, ConvergedResultsList)),
    ok.

two_pid_dying_test(Config) ->
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config),
    Module = proplists:get_value(module, Config),
    Msg = proplists:get_value(msg, Config),
    S0 = hbbft_rbc:init(N, F, 0, 0),
    S1 = hbbft_rbc:init(N, F, 1, 0),
    S3 = hbbft_rbc:init(N, F, 3, 0),
    {NewS0, {send, MsgsToSend}} = hbbft_rbc:input(S0, Msg),
    States = [NewS0, S1, S3],
    StatesWithId = lists:zip(lists:seq(0, length(States) - 1), States),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(Module, [{0, {send, MsgsToSend}}], StatesWithId, sets:new()),
    %% nobody should converge
    ?assertEqual(0, sets:size(ConvergedResults)),
    ok.

simple_test(Config) ->
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config),
    Msg = proplists:get_value(msg, Config),
    Leader = rand:uniform(N) - 1,
    Workers = [element(2, rbc_worker:start_link(N, F, Id, Leader)) || Id <- lists:seq(0, N-1)],

    %% the first guy is the leader
    ok = rbc_worker:input(Msg, lists:nth(Leader+1, Workers)),

    hbbft_ct_utils:wait_until(fun() ->
                                      lists:all(fun(E) ->
                                                        E /= undefined
                                                end, [rbc_worker:get_results(W) || W <- Workers])
                              end),

    ConvergedResults = [rbc_worker:get_results(W) || W <- Workers],
    1 = sets:size(sets:from_list(ConvergedResults)),
    Msg = hd(ConvergedResults),
    ok.
