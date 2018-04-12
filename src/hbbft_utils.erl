-module(hbbft_utils).

-export([share_to_binary/1, binary_to_share/2, wrap/2]).

share_to_binary({ShareIdx, ShareElement}) ->
    %% Assume less than 256 members in the consensus group
    ShareBinary = erlang_pbc:element_to_binary(ShareElement),
    <<ShareIdx:8/integer-unsigned, ShareBinary/binary>>.

binary_to_share(<<ShareIdx:8/integer-unsigned, ShareBinary/binary>>, SK) ->
    %% XXX we don't have a great way to deserialize the elements yet, this is a hack
    Ugh = tpke_pubkey:hash_message(tpke_privkey:public_key(SK), <<"ugh">>),
    ShareElement = erlang_pbc:binary_to_element(Ugh, ShareBinary),
    {ShareIdx, ShareElement}.

%% wrap a subprotocol's outbound messages with a protocol identifier
wrap(_, []) ->
    [];
wrap(Id, [{multicast, Msg}|T]) ->
    [{multicast, {Id, Msg}}|wrap(Id, T)];
wrap(Id, [{unicast, Dest, Msg}|T]) ->
    [{unicast, Dest, {Id, Msg}}|wrap(Id, T)].
