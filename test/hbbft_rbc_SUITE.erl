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
    N = list_to_integer(os:getenv("N", 34)),
    F = (N - 1) div 3,
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
    [S0 | SN] = [ hbbft_rbc:init(N, F, I, 0) || I <- lists:seq(0, N-1) ],
    {NewS0, {send, MsgsToSend}} = hbbft_rbc:input(S0, Msg),
    States = [NewS0 | SN],
    StatesWithId = lists:zip(lists:seq(0, length(States) - 1), States),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(Module, [{0, {send, MsgsToSend}}], StatesWithId, sets:new()),
    %% everyone should converge
    ?assertEqual(N, sets:size(ConvergedResults)),
    %% the decoded result should be the original message
    ConvergedResultsList = sets:to_list(ConvergedResults),
    ct:pal("ConvergedResultsList: ~p~n", [ConvergedResultsList]),
    ?assert(lists:all(fun({result, {_, Res}}) -> Res == Msg end, ConvergedResultsList)),
    ok.

send_incorrect_msg_test(Config) ->
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config),
    Module = proplists:get_value(module, Config),
    Msg = proplists:get_value(msg, Config),
    [S0 | SN] = [ hbbft_rbc:init(N, F, I, 0) || I <- lists:seq(0, N-1) ],
    {NewS0, {send, MsgsToSend}} = hbbft_rbc:input(S0, Msg),

    {unicast, _, {val, MerkleRootHash, _, _}} = hd(MsgsToSend),

    %% ====================================================
    %% screw up M val messages in the MsgsToSend
    %% TODO: something better but this works for now
    BadMsg = crypto:strong_rand_bytes(512),
    M = N - 2*F,
    K = 2*F,
    {ok, Shards} = erasure:encode(K, M, BadMsg),
    MsgSize = byte_size(BadMsg),
    ShardsWithSize = [{MsgSize, Shard} || Shard <- Shards],
    Merkle = merkerl:new(ShardsWithSize, fun merkerl:hash_value/1),
    BranchesForShards = [merkerl:gen_proof(Hash, Merkle) || {Hash, _} <- merkerl:leaves(Merkle)],
    BadMsgsToSend = [ {unicast, J, {val, MerkleRootHash, lists:nth(J+1, BranchesForShards), lists:nth(J+1, ShardsWithSize)}} || J <- lists:seq(0, N-1)],
    Msgs1 = lists:sublist(MsgsToSend, K),
    Msgs2 = lists:sublist(BadMsgsToSend, K+1, M),
    NewMsgsToSend = Msgs1 ++ Msgs2,
    %% ====================================================

    States = [NewS0 | SN],
    StatesWithId = lists:zip(lists:seq(0, length(States) - 1), States),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(Module, [{0, {send, NewMsgsToSend}}], StatesWithId, sets:new()),
    ConvergedResultsList = sets:to_list(ConvergedResults),
    ct:pal("ConvergedResultsList: ~p~n", [ConvergedResultsList]),
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
    [S0 | SN] = [ hbbft_rbc:init(N, F, I, 0) || I <- lists:seq(0, N-1 - F - 1) ],
    %% different leader than the one who proposed to start RBC
    SN2 = [ hbbft_rbc:init(N, F, I, 1) || I <- lists:seq((2*F), N-1) ],
    {NewS0, {send, MsgsToSend}} = hbbft_rbc:input(S0, Msg),
    States = [NewS0] ++ SN ++ SN2,
    ?assertEqual(N, length(States)),
    StatesWithId = lists:zip(lists:seq(0, length(States) - 1), States),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(Module, [{0, {send, MsgsToSend}}], StatesWithId, sets:new()),
    ConvergedResultsList = sets:to_list(ConvergedResults),
    ct:pal("ConvergedResultsList: ~p~n", [ConvergedResultsList]),
    %% no one should converge
    ?assertEqual(0, sets:size(ConvergedResults)),
    ok.

pid_dying_test(Config) ->
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config),
    Module = proplists:get_value(module, Config),
    Msg = proplists:get_value(msg, Config),
    [S0, S1, _S2 | SN] = [ hbbft_rbc:init(N, F, I, 0) || I <- lists:seq(0, N-1) ],
    {NewS0, {send, MsgsToSend}} = hbbft_rbc:input(S0, Msg),
    States = [NewS0, S1 | SN],
    StatesWithId = lists:zip(lists:seq(0, length(States) - 1), States),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(Module, [{0, {send, MsgsToSend}}], StatesWithId, sets:new()),
    %% everyone but the dead node should converge
    ?assertEqual(N - 1, sets:size(ConvergedResults)),
    %% the decoded result should be the original message
    ConvergedResultsList = sets:to_list(ConvergedResults),
    ct:pal("ConvergedResultsList: ~p~n", [ConvergedResultsList]),
    ?assert(lists:all(fun({result, {_, Res}}) -> Res == Msg end, ConvergedResultsList)),
    ok.

two_pid_dying_test(Config) ->
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config),
    Module = proplists:get_value(module, Config),
    Msg = proplists:get_value(msg, Config),
    [S0 | SN] = [ hbbft_rbc:init(N, F, I, 0) || I <- lists:seq(0, N-1 - (2*F)) ],
    {NewS0, {send, MsgsToSend}} = hbbft_rbc:input(S0, Msg),
    States = [NewS0 | SN],
    ?assertEqual(N-(2*F), length(States)),
    StatesWithId = lists:zip(lists:seq(0, length(States) - 1), States),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(Module, [{0, {send, MsgsToSend}}], StatesWithId, sets:new()),
    ConvergedResultsList = sets:to_list(ConvergedResults),
    ct:pal("ConvergedResultsList: ~p~n", [ConvergedResultsList]),
    %% nobody should converge
    ?assertEqual(0, sets:size(ConvergedResults)),
    ok.

simple_test(Config) ->
    N = proplists:get_value(n, Config),
    F = proplists:get_value(f, Config),
    Msg = proplists:get_value(msg, Config),
    Leader = rand:uniform(N) - 1,
    Workers = [element(2, hbbft_rbc_worker:start_link(N, F, Id, Leader)) || Id <- lists:seq(0, N-1)],

    %% the first guy is the leader
    ok = hbbft_rbc_worker:input(Msg, lists:nth(Leader+1, Workers)),

    hbbft_ct_utils:wait_until(fun() ->
                                      lists:all(fun(E) ->
                                                        E /= undefined
                                                end, [hbbft_rbc_worker:get_results(W) || W <- Workers])
                              end),

    ConvergedResults = [hbbft_rbc_worker:get_results(W) || W <- Workers],
    ct:pal("ConvergedResults: ~p~n", [ConvergedResults]),
    1 = sets:size(sets:from_list(ConvergedResults)),
    Msg = hd(ConvergedResults),
    ok.
