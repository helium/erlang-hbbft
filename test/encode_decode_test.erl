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
	%% io:format("Msg: ~p~n", [Msg]),
	Threshold = N - 2*F,
	%% io:format("Threshold: ~p~n", [Threshold]),
	{ok, Sj} = leo_erasure:encode({Threshold, N}, Msg),
	%% io:format("Sj: ~p~n", [Sj]),
	Bits = random_n(Threshold, Sj),
	%% io:format("Bits: ~p~n", [Bits]),
	{ok, Bin} = leo_erasure:decode({Threshold, N}, Bits, byte_size(Msg)),
	%% io:format("Bin: ~p~n", [Bin]),
	Bin == Msg.

%% helpers
random_n(N, List) ->
    lists:sublist(shuffle(List), N).

shuffle(List) ->
    [X || {_,X} <- lists:sort([{rand:uniform(), N} || N <- List])].
