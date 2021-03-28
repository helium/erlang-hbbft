-module(hbbft_utils).

-type multicast(Msg) :: {multicast, Msg}.
-type unicast(Msg) :: {unicast, J :: non_neg_integer(), Msg}.

-export_type([unicast/1, multicast/1]).

-export([sig_share_to_binary/1, binary_to_sig_share/1, dec_share_to_binary/1, binary_to_dec_share/1, wrap/2, random_n/2, shuffle/1]).

sig_share_to_binary({ShareIdx, SigShare}) ->
    %% Assume less than 256 members in the consensus group
    ShareBinary = signature_share:serialize(SigShare),
    <<ShareIdx:8/integer-unsigned, ShareBinary/binary>>.

binary_to_sig_share(<<ShareIdx:8/integer-unsigned, ShareBinary/binary>>) ->
    SigShare = signature_share:deserialize(ShareBinary),
    {ShareIdx, SigShare}.

dec_share_to_binary({ShareIdx, DecShare}) ->
    %% Assume less than 256 members in the consensus group
    ShareBinary = decryption_share:serialize(DecShare),
    <<ShareIdx:8/integer-unsigned, ShareBinary/binary>>.

binary_to_dec_share(<<ShareIdx:8/integer-unsigned, ShareBinary/binary>>) ->
    DecShare = decryption_share:deserialize(ShareBinary),
    {ShareIdx, DecShare}.


%% wrap a subprotocol's outbound messages with a protocol identifier
-spec wrap(Tag :: atom() | {atom(), non_neg_integer()}, [{multicast, Msg :: any()} | {unicast, non_neg_integer(),  Msg :: any()}]) -> [{multicast, {Tag, Msg}} | {unicast, non_neg_integer(), {Tag, Msg}}].
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
