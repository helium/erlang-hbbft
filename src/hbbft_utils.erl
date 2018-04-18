-module(hbbft_utils).

-type multicast(Msg) :: {multicast, Msg}.
-type unicast(Msg) :: {unicast, J :: non_neg_integer(), Msg}.

-export_type([unicast/1, multicast/1]).

-export([share_to_binary/1, binary_to_share/2, wrap/2, random_n/2, shuffle/1]).

-spec share_to_binary({non_neg_integer(), erlang_pbc:element()}) -> binary().
share_to_binary({ShareIdx, ShareElement}) ->
    %% Assume less than 256 members in the consensus group
    ShareBinary = erlang_pbc:element_to_binary(ShareElement),
    <<ShareIdx:8/integer-unsigned, ShareBinary/binary>>.

-spec binary_to_share(binary(), tpke_privkey:privkey()) -> {non_neg_integer(), erlang_pbc:element()}.
binary_to_share(<<ShareIdx:8/integer-unsigned, ShareBinary/binary>>, SK) ->
    %% XXX we don't have a great way to deserialize the elements yet, this is a hack
    Ugh = tpke_pubkey:hash_message(tpke_privkey:public_key(SK), <<"ugh">>),
    ShareElement = erlang_pbc:binary_to_element(Ugh, ShareBinary),
    {ShareIdx, ShareElement}.

%% wrap a subprotocol's outbound messages with a protocol identifier
-spec wrap(atom() | {atom(), non_neg_integer()}, list()) -> list().
wrap(_, []) ->
    [];
wrap(Id, [{multicast, Msg}|T]) ->
    [{multicast, {Id, Msg}}|wrap(Id, T)];
wrap(Id, [{unicast, Dest, Msg}|T]) ->
    [{unicast, Dest, {Id, Msg}}|wrap(Id, T)].

-spec random_n(pos_integer(), list()) -> list().
random_n(N, List) ->
    lists:sublist(shuffle(List), N).

-spec shuffle(list()) -> list().
shuffle(List) ->
    [X || {_,X} <- lists:sort([{rand:uniform(), N} || N <- List])].
