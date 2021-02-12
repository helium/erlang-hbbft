-module(encode_decode_test).

-include_lib("eunit/include/eunit.hrl").

encoded_decoded_equality_test() ->
    %% Test some random bytes
    %% TODO: eqc probably?
    ?assert(encoded_decoded_equality_test(14, 4, crypto:strong_rand_bytes(32))),
    ?assert(encoded_decoded_equality_test(14, 4, crypto:strong_rand_bytes(256))),
    ?assert(encoded_decoded_equality_test(14, 4, crypto:strong_rand_bytes(512))),
    ?assert(encoded_decoded_equality_test(14, 4, crypto:strong_rand_bytes(1024))).

encoded_decoded_equality_test(N, F, Msg) ->
	%% ct:log("Msg: ~p~n", [Msg]),
	Threshold = N - 2*F,
	%% ct:log("Threshold: ~p~n", [Threshold]),
	{ok, Sj} = erasure:encode(Threshold, N, Msg),
	%% ct:log("Sj: ~p~n", [Sj]),
	Bits = random_n(Threshold, Sj),
	%% ct:log("Bits: ~p~n", [Bits]),
	{ok, Bin} = erasure:decode(Threshold, N, Bits),
	%% ct:log("Bin: ~p~n", [Bin]),
	Bin == Msg.

%% helpers
random_n(N, List) ->
    lists:sublist(shuffle(List), N).

shuffle(List) ->
    [X || {_,X} <- lists:sort([{rand:uniform(), N} || N <- List])].
