-module(hbbft_SUITE).

-include_lib("common_test/include/ct.hrl").

-export([all/0, init_per_testcase/2, end_per_testcase/2]).
-export([simple_test/1]).

all() ->
    [simple_test].

init_per_testcase(_, Config) ->
    Config.

end_per_testcase(_, _) ->
    ok.

simple_test(_Config) ->
    N=5,
    F=(N div 3),
    BatchSize = 20,
    dealer:start_link(N, F+1, 'SS512'),
    {ok, PubKey, PrivateKeys} = dealer:deal(),
    gen_server:stop(dealer),
    Workers = [ element(2, hbbft_worker:start_link(N, F, I, tpke_privkey:serialize(SK), BatchSize, false)) || {I, SK} <- enumerate(PrivateKeys) ],
    Msgs = [ crypto:strong_rand_bytes(128) || _ <- lists:seq(1, N*20)],
    %% feed the badgers some msgs
    lists:foreach(fun(Msg) ->
                          Destinations = random_n(rand:uniform(N), Workers),
                          io:format("destinations ~p~n", [Destinations]),
                          [ok = hbbft_worker:submit_transaction(Msg, D) || D <- Destinations]
                  end, Msgs),

    %% wait for all the worker's mailboxes to settle and
    %% wait for the chains to converge
    ok = hbbft_ct_utils:wait_until(fun() ->
                                           Chains = sets:from_list(lists:map(fun(W) ->
                                                                                     {ok, Blocks} = hbbft_worker:get_blocks(W),
                                                                                     Blocks
                                                                             end, Workers)),

                                           0 == lists:sum([element(2, erlang:process_info(W, message_queue_len)) || W <- Workers ]) andalso
                                           1 == sets:size(Chains) andalso
                                           0 /= length(hd(sets:to_list(Chains)))
                                   end, 60*2, 500),


    Chains = sets:from_list(lists:map(fun(W) ->
                                              {ok, Blocks} = hbbft_worker:get_blocks(W),
                                              Blocks
                                      end, Workers)),
    1 = sets:size(Chains),
    [Chain] = sets:to_list(Chains),
    io:format("chain is of height ~p~n", [length(Chain)]),
    %% verify they are cryptographically linked
    true = hbbft_worker:verify_chain(Chain, PubKey),
    %% check all the transactions are unique
    BlockTxns = lists:flatten([ hbbft_worker:block_transactions(B) || B <- Chain ]),
    true = length(BlockTxns) == sets:size(sets:from_list(BlockTxns)),
    %% check they're all members of the original message list
    true = sets:is_subset(sets:from_list(BlockTxns), sets:from_list(Msgs)),
    io:format("chain contains ~p distinct transactions~n", [length(BlockTxns)]),
    ok.

enumerate(List) ->
    lists:zip(lists:seq(0, length(List) - 1), List).

random_n(N, List) ->
    lists:sublist(shuffle(List), N).

shuffle(List) ->
    [X || {_,X} <- lists:sort([{rand:uniform(), N} || N <- List])].

