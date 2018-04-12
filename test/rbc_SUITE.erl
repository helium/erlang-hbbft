-module(rbc_SUITE).

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
    N = 5,
    F = (N div 3),
    Msg = crypto:strong_rand_bytes(512),
    Workers = [element(2, rbc_worker:start_link(N, F, Id)) || Id <- lists:seq(1, N)],
    Destinations = random_n(rand:uniform(N), Workers),
    ConvergedResults = [rbc_worker:get_results(Msg, D) || D <- Destinations],
    0 = sets:size(ConvergedResults),
    ok.

random_n(N, List) ->
    lists:sublist(shuffle(List), N).

shuffle(List) ->
    [X || {_,X} <- lists:sort([{rand:uniform(), N} || N <- List])].

