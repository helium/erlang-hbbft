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
    Workers = [element(2, rbc_worker:start_link(N, F, Id)) || Id <- lists:seq(0, N-1)],
    ok = rbc_worker:input(Msg, hd(random_n(1, Workers))),

    wait_until(fun() ->
                       lists:all(fun(E) ->
                                         E /= undefined
                                 end, [rbc_worker:get_results(W) || W <- Workers])
               end),

    ConvergedResults = [rbc_worker:get_results(W) || W <- Workers],
    1 = sets:size(sets:from_list(ConvergedResults)),
    Msg = hd(ConvergedResults),
    ok.

random_n(N, List) ->
    lists:sublist(shuffle(List), N).

shuffle(List) ->
    [X || {_,X} <- lists:sort([{rand:uniform(), N} || N <- List])].

wait_until(Fun) ->
    wait_until(Fun, 40, 100).

wait_until(Fun, Retry, Delay) when Retry > 0 ->
    Res = Fun(),
    case Res of
        true ->
            ok;
        _ when Retry == 1 ->
            {fail, Res};
        _ ->
            timer:sleep(Delay),
            wait_until(Fun, Retry-1, Delay)
    end.
