-module(hbbft_rbc).

-export([init/2, input/2, handle_msg/3]).

-record(rbc_data, {
          state = init :: init | waiting | done,
          n :: pos_integer(),
          f :: non_neg_integer(),
          msg = undefined :: binary() | undefined,
          h = undefined :: binary() | undefined,
          shares = [] :: [{merkerl:proof(), {pos_integer(), binary()}}],
          num_echoes = [] :: [non_neg_integer()],
          num_readies = [] :: [non_neg_integer()],
          seen_val = false :: boolean(),
          ready_sent = false :: boolean()
         }).

%% rbc protocol requires three message types: ECHO(h, bj, sj), VAL(h, bj, sj) and READY(h)
%% where h: merkle hash, bj: merkle branch (proof) and sj: blocks of (N-2f, N)-erasure coding scheme applied to input
-type val_msg() :: {val, merkerl:hash(), merkerl:proof(), {non_neg_integer(), binary()}}.
-type echo_msg() :: {echo, merkerl:hash(), merkerl:proof(), {non_neg_integer(), binary()}}.
-type ready_msg() :: {ready, merkerl:hash()}.
-type msgs() :: val_msg() | echo_msg() | ready_msg().

%% rbc can multicast ECHO and READY msgs but it only unicasts VAL msg
-type send_commands() :: [hbbft_utils:unicast(val_msg()) | hbbft_utils:multicast(echo_msg() | ready_msg())].

-type rbc_data() :: #rbc_data{}.

-export_type([rbc_data/0, val_msg/0, echo_msg/0, ready_msg/0, msgs/0]).

%% API.
-spec init(pos_integer(), non_neg_integer()) -> rbc_data().
init(N, F) ->
    #rbc_data{n=N, f=F}.

%% Figure2. Bullet1
%% let {Sj} j∈[N] be the blocks of an (N − 2 f , N)-erasure coding
%% scheme applied to v
%% let h be a Merkle tree root computed over {Sj}
%% send VAL(h, b j , s j ) to each party P j , where b j is the jth
%% Merkle tree branch
-spec input(rbc_data(), binary()) -> {rbc_data(), {send, send_commands()}}.
input(Data = #rbc_data{state=init, n=N, f=F}, Msg) ->
    %% (N-2f, N)-erasure coding scheme applied to input
    M = N - 2*F,
    K = 2*F,
    %% Shards represent sj from the whitepaper
    {ok, Shards} = leo_erasure:encode({K, M}, Msg),
    %% Need to know the size of the msg for decoding
    MsgSize = byte_size(Msg),
    ShardsWithSize = [{MsgSize, Shard} || Shard <- Shards],
    Merkle = merkerl:new(ShardsWithSize, fun merkerl:hash_value/1),
    MerkleRootHash = merkerl:root_hash(Merkle),
    %% gen_proof = branches for each merkle node (Hash(shard))
    BranchesForShards = [merkerl:gen_proof(Hash, Merkle) || {Hash, _} <- merkerl:leaves(Merkle)],
    %% TODO add our identity to the ready/echo sets?
    NewData = Data#rbc_data{msg=Msg, h=MerkleRootHash},
    Result = [ {unicast, J, {val, MerkleRootHash, lists:nth(J+1, BranchesForShards), lists:nth(J+1, ShardsWithSize)}} || J <- lists:seq(0, N-1)],
    %% unicast all the VAL packets and multicast the ECHO for our own share
    {NewData#rbc_data{state=waiting}, {send, Result}}. % ++ [{multicast, {echo, MerkleRootHash, hd(BranchesForShards), hd(ShardsWithSize)}}]}}.


%% message handlers
-spec handle_msg(rbc_data(), non_neg_integer(), val_msg() | echo_msg() | ready_msg()) -> {rbc_data(), ok | {send, send_commands()}} |
                                                                                         {rbc_data(), ok | {send, send_commands()} | {result, V :: binary()} | abort} |
                                                                                         {rbc_data(), ok | {send, send_commands()} | {result, V :: binary()}}.

handle_msg(Data, J, {val, H, Bj, Sj}) ->
    val(Data, J, H, Bj, Sj);
handle_msg(Data, J, {echo, H, Bj, Sj}) ->
    echo(Data, J, H, Bj, Sj);
handle_msg(Data, J, {ready, H}) ->
    ready(Data, J, H).


%% Figure2. Bullet2
%% upon receiving VAL(h, bi , si) from PSender,
%% multicast ECHO(h, bi , si )
-spec val(rbc_data(), non_neg_integer(), merkerl:hash(), merkerl:proof(), binary()) -> {rbc_data(), ok | {send, send_commands()}}.
val(Data = #rbc_data{seen_val=false}, _J, H, Bj, Sj) ->
    NewShares = [ {Bj, Sj} | Data#rbc_data.shares ],
    NewData = Data#rbc_data{h=H, shares=NewShares, seen_val=true},
    {NewData, {send, [{multicast, {echo, H, Bj, Sj}}]}};
val(Data, J, _H, _Bi, _Si) ->
    %% we already had a val, just ignore this
    io:format("~p ignoring duplicate VAL msg from ~p~n", [self(), J]),
    {Data, ok}.


%% Figure2. Bullet3
%% upon receiving ECHO(h, bj, sj ) from party Pj ,
%% check that bj is a valid Merkle branch for root h and leaf sj ,
%% and otherwise discard
-spec echo(rbc_data(), non_neg_integer(), merkerl:hash(), merkerl:proof(), binary()) -> {rbc_data(), ok | {send, send_commands()} | {result, V :: binary()} | abort}.
echo(Data = #rbc_data{state=done}, _J, _H, _Bj, _Sj) ->
    {Data, ok};
echo(Data = #rbc_data{n=N, f=F}, J, H, Bj, Sj) ->
    case merkerl:verify_proof(merkerl:hash_value(Sj), H, Bj) of
        ok ->
            %% valid branch
            NewData = Data#rbc_data{h=H, shares=lists:usort([{Bj, Sj} | Data#rbc_data.shares]), num_echoes=insert_once(J, Data#rbc_data.num_echoes)},
            case length(NewData#rbc_data.num_echoes) >= (N - F) andalso length(NewData#rbc_data.shares) >= (N - 2*F) of
                true ->
                    %% Figure2. Bullet4
                    %% upon receiving valid ECHO(h, ·, ·) messages from N − f distinct parties,
                    %% – interpolate {s0 j} from any N − 2 f leaves received
                    %% – recompute Merkle root h0 and if h0 /= h then abort
                    %% – if READY(h) has not yet been sent, multicast READY(h)
                    check_completion(NewData, H);
                false ->
                    {NewData#rbc_data{state=waiting}, ok}
            end;
        {error, _} ->
            %% otherwise discard
            {Data, ok}
    end.

%% Figure2. Bullet5
%% upon receiving f + 1 matching READY(h) messages, if READY
%% has not yet been sent, multicast READY(h)
-spec ready(rbc_data(), non_neg_integer(), merkerl:hash()) -> {rbc_data(), ok | {send, send_commands()} | {result, V :: binary()}}.
ready(Data = #rbc_data{state=waiting, n=N, f=F, h=H}, J, H) ->
    %% increment num_readies
    NewData = Data#rbc_data{num_readies=insert_once(J, Data#rbc_data.num_readies)},
    case length(NewData#rbc_data.num_readies) >= F + 1 andalso length(NewData#rbc_data.shares) >= (N - 2*F) of
        true ->
            check_completion(NewData, H);
        false ->
            %% waiting
            {NewData, ok}
    end;
ready(Data, J, _H) ->
    io:format("Ignoring result from ~p in state ~p~n", [J, Data#rbc_data.state]),
    {Data, ok}.


%% helper to check whether rbc protocol has completed
-spec check_completion(rbc_data(), merkerl:hash()) -> {rbc_data(), ok | {result, binary()} | hbbft_utils:multicast(ready_msg()) | {result, aborted}}.
check_completion(Data = #rbc_data{n=N, f=F}, H) ->
    %% interpolate Sj from any N-2f leaves received

    %% From leo_erasure:
    %% Object would be encoded into {k + m} blocks, any {k} blocks could be used to decode back
    %% K: The number of data chunks - The number of chunks in which the original object is divided
    %% M: The number of coding chunks - The number of additional chunks computed by leo_erasure's encoding functions
    M = N - 2*F, %% Note: M = Threshold (specified in RBC protocol)
    K = 2*F,

    {_, ShardsWithSize} = lists:unzip(Data#rbc_data.shares),
    {_, Shards} = lists:unzip(ShardsWithSize),
    case leo_erasure:decode({K, M}, Shards, element(1, hd(ShardsWithSize))) of
        {ok, Msg} ->
            %% recompute merkle root H
            MsgSize = byte_size(Msg),
            {ok, AllShards} = leo_erasure:encode({K, M}, Msg),
            AllShardsWithSize = [{MsgSize, Shard} || Shard <- AllShards],
            Merkle = merkerl:new(AllShardsWithSize, fun merkerl:hash_value/1),
            MerkleRootHash = merkerl:root_hash(Merkle),
            case H == MerkleRootHash of
                true ->
                    %% root hashes match
                    %% check if ready already sent
                    case Data#rbc_data.ready_sent of
                        true ->
                            %% Figure2. Bullet6
                            %% check if we have enough readies and enough echoes
                            %% N-2F echoes and 2F + 1 readies
                            case length(Data#rbc_data.num_echoes) >= M andalso length(Data#rbc_data.num_readies) >= (2*F + 1) of
                                true ->
                                    %% decode V. Done
                                    {Data#rbc_data{state=done}, {result, Msg}};
                                false ->
                                    %% wait for enough echoes and readies?
                                    {Data#rbc_data{state=waiting, msg=Msg}, ok}
                            end;
                        false ->
                            %% send ready(h)
                            {Data#rbc_data{state=waiting, msg=Msg, ready_sent=true}, {send, [{multicast, {ready, H}}]}}
                    end;
                false ->
                    %% abort
                    {Data#rbc_data{state=done}, {result, aborted}}
            end;
        {error, _Reason} ->
            {Data#rbc_data{state=waiting}, ok}
    end.

-spec insert_once(non_neg_integer(), [non_neg_integer()]) -> [non_neg_integer(), ...].
insert_once(Element, List) ->
    case lists:member(Element, List) of
        true -> List;
        false -> [Element | List]
    end.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

init_test() ->
    N = 5,
    F = 1,
    Msg = crypto:strong_rand_bytes(512),
    S0 = hbbft_rbc:init(N, F),
    S1 = hbbft_rbc:init(N, F),
    S2 = hbbft_rbc:init(N, F),
    S3 = hbbft_rbc:init(N, F),
    S4 = hbbft_rbc:init(N, F),
    {NewS0, {send, MsgsToSend}} = hbbft_rbc:input(S0, Msg),
    States = [NewS0, S1, S2, S3, S4],
    StatesWithId = lists:zip(lists:seq(0, length(States) - 1), States),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(?MODULE, [{0, {send, MsgsToSend}}], StatesWithId, sets:new()),
    %% everyone should converge
    ?assertEqual(N, sets:size(ConvergedResults)),
    %% the decoded result should be the original message
    ConvergedResultsList = sets:to_list(ConvergedResults),
    ?assert(lists:all(fun({result, {_, Res}}) -> Res == Msg end, ConvergedResultsList)),
    ok.

send_incorrect_msg_test() ->
    N = 5,
    F = 1,
    Msg = crypto:strong_rand_bytes(512),
    S0 = hbbft_rbc:init(N, F),
    S1 = hbbft_rbc:init(N, F),
    S2 = hbbft_rbc:init(N, F),
    S3 = hbbft_rbc:init(N, F),
    S4 = hbbft_rbc:init(N, F),
    {NewS0, {send, MsgsToSend}} = hbbft_rbc:input(S0, Msg),

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
    MerkleRootHash = merkerl:root_hash(Merkle),
    BranchesForShards = [merkerl:gen_proof(Hash, Merkle) || {Hash, _} <- merkerl:leaves(Merkle)],
    BadMsgsToSend = [ {unicast, J, {val, MerkleRootHash, lists:nth(J+1, BranchesForShards), lists:nth(J+1, ShardsWithSize)}} || J <- lists:seq(0, N-1)],
    [ First, Second | _ ] = MsgsToSend,
    [ Third, Fourth, Fifth | _ ] = BadMsgsToSend,
    NewMsgsToSend = [First, Second, Third, Fourth, Fifth],
    %% ====================================================

    States = [NewS0, S1, S2, S3, S4],
    StatesWithId = lists:zip(lists:seq(0, length(States) - 1), States),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(?MODULE, [{0, {send, NewMsgsToSend}}], StatesWithId, sets:new()),
    %% no one should converge
    ?assertEqual(0, sets:size(ConvergedResults)),
    ok.

pid_dying_test() ->
    N = 5,
    F = 1,
    Msg = crypto:strong_rand_bytes(512),
    S0 = hbbft_rbc:init(N, F),
    S1 = hbbft_rbc:init(N, F),
    S3 = hbbft_rbc:init(N, F),
    S4 = hbbft_rbc:init(N, F),
    {NewS0, {send, MsgsToSend}} = hbbft_rbc:input(S0, Msg),
    States = [NewS0, S1, S3, S4],
    StatesWithId = lists:zip(lists:seq(0, length(States) - 1), States),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(?MODULE, [{0, {send, MsgsToSend}}], StatesWithId, sets:new()),
    %% everyone but the dead node should converge
    ?assertEqual(N - 1, sets:size(ConvergedResults)),
    %% the decoded result should be the original message
    ConvergedResultsList = sets:to_list(ConvergedResults),
    ?assert(lists:all(fun({result, {_, Res}}) -> Res == Msg end, ConvergedResultsList)),
    ok.

two_pid_dying_test() ->
    N = 5,
    F = 1,
    Msg = crypto:strong_rand_bytes(512),
    S0 = hbbft_rbc:init(N, F),
    S1 = hbbft_rbc:init(N, F),
    S3 = hbbft_rbc:init(N, F),
    {NewS0, {send, MsgsToSend}} = hbbft_rbc:input(S0, Msg),
    States = [NewS0, S1, S3],
    StatesWithId = lists:zip(lists:seq(0, length(States) - 1), States),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(?MODULE, [{0, {send, MsgsToSend}}], StatesWithId, sets:new()),
    %% nobody should converge
    ?assertEqual(0, sets:size(ConvergedResults)),
    ok.
-endif.
