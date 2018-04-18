-module(hbbft_rbc).

-export([init/2, input/2, handle_msg/3]).

-record(rbc_data, {
          state = init :: init | waiting | aborted | done,
          n :: pos_integer(),
          f :: non_neg_integer(),
          msg = undefined :: binary() | undefined,
          h = undefined :: binary() | undefined,
          shares = [] :: [{merkerl:proof(), {pos_integer(), binary()}}],
          num_echoes = sets:new() :: sets:set(non_neg_integer()),
          num_readies = sets:new() :: sets:set(non_neg_integer()),
          ready_sent = false :: boolean()
         }).

-type val_msg() :: {val, merkerl:hash(), merkerl:proof(), {non_neg_integer(), binary()}}.
-type echo_msg() :: {echo, merkerl:hash(), merkerl:proof(), {non_neg_integer(), binary()}}.
-type ready_msg() :: {ready, merkerl:hash()}.
-type msgs() :: val_msg() | echo_msg() | ready_msg().

-type send_commands() :: [hbbft_utils:unicast(val_msg()) | hbbft_utils:multicast(echo_msg() | ready_msg())].

-type rbc_data() :: #rbc_data{}.

-export_type([rbc_data/0, val_msg/0, echo_msg/0, ready_msg/0, msgs/0]).

%% API.
-spec init(pos_integer(), non_neg_integer()) -> rbc_data().
init(N, F) ->
    #rbc_data{n=N, f=F}.

-spec input(rbc_data(), binary()) -> {rbc_data(), {send, send_commands()}}.
input(Data = #rbc_data{state=init, n=N, f=F}, Msg) ->
    %% Figure2 from honeybadger WP
    %%%% let {Sj} j∈[N] be the blocks of an (N − 2 f , N)-erasure coding
    %%%% scheme applied to v
    %%%% let h be a Merkle tree root computed over {Sj}
    %%%% send VAL(h, b j , s j ) to each party P j , where b j is the jth
    %%%% Merkle tree branch
    Threshold = N - 2*F,
    {ok, Shards} = leo_erasure:encode({Threshold, N - Threshold}, Msg),
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
    {NewData#rbc_data{state=waiting}, {send, Result ++ [{multicast, {echo, MerkleRootHash, hd(BranchesForShards), hd(ShardsWithSize)}}]}}.

-spec handle_msg(rbc_data(), non_neg_integer(), val_msg() | echo_msg() | ready_msg()) -> {rbc_data(), ok | {send, send_commands()}} |
                                                                                         {rbc_data(), ok | {send, send_commands()} | {result, V :: binary()} | abort} |
                                                                                         {rbc_data(), ok | {send, send_commands()} | {result, V :: binary()}}.

handle_msg(Data, _J, {val, H, Bj, Sj}) ->
    val(Data, H, Bj, Sj);
handle_msg(Data, J, {echo, H, Bj, Sj}) ->
    echo(Data, J, H, Bj, Sj);
handle_msg(Data, J, {ready, H}) ->
    ready(Data, J, H).

-spec val(rbc_data(), merkerl:hash(), merkerl:proof(), binary()) -> {rbc_data(), ok | {send, send_commands()}}.
val(Data = #rbc_data{state=init}, H, Bj, Sj) ->
    NewData = Data#rbc_data{h=H, shares=[{Bj, Sj}]},
    {NewData, {send, [{multicast, {echo, H, Bj, Sj}}]}};
val(Data, _H, _Bi, _Si) ->
    %% we already had a val, just ignore this
    {Data, ok}.

-spec echo(rbc_data(), non_neg_integer(), merkerl:hash(), merkerl:proof(), binary()) -> {rbc_data(), ok | {send, send_commands()} | {result, V :: binary()} | abort}.
echo(Data = #rbc_data{state=aborted}, _J, _H, _Bj, _Sj) ->
    {Data, ok};
echo(Data = #rbc_data{state=done}, _J, _H, _Bj, _Sj) ->
    {Data, ok};
echo(Data = #rbc_data{n=N, f=F}, J, H, Bj, Sj) ->
    %% Check that Bj is a valid merkle branch for root h and and leaf Sj
    case merkerl:verify_proof(merkerl:hash_value(Sj), H, Bj) of
        ok ->
            NewData = Data#rbc_data{h=H, shares=lists:usort([{Bj, Sj}|Data#rbc_data.shares]), num_echoes=sets:add_element(J, Data#rbc_data.num_echoes)},
            case sets:size(NewData#rbc_data.num_echoes) >= (N - F) of
                true ->
                    check_completion(NewData, H);
                false ->
                    {NewData#rbc_data{state=waiting}, ok}
            end;
        {error, _} ->
            %% otherwise discard
            {Data, ok}
    end.


-spec ready(rbc_data(), non_neg_integer(), merkerl:hash()) -> {rbc_data(), ok | {send, send_commands()} | {result, V :: binary()}}.
ready(Data = #rbc_data{state=waiting, f=F, h=H}, J, H) ->
    %% increment num_readies
    NewData = Data#rbc_data{num_readies=sets:add_element(J, Data#rbc_data.num_readies)},
    case sets:size(NewData#rbc_data.num_readies) >= F + 1 of
        true ->
            check_completion(NewData, H);
        false ->
            %% waiting
            {NewData, ok}
    end;
ready(Data, _J, _H) ->
    {Data, ok}.

-spec check_completion(rbc_data(), merkerl:hash()) -> {rbc_data(), ok | {result, binary()} | hbbft_utils:multicast(ready_msg()) | abort}.
check_completion(Data = #rbc_data{n=N, f=F}, H) ->
    %% interpolate Sj from any N-2f leaves received
    Threshold = N - 2*F,
    {_, ShardsWithSize} = lists:unzip(Data#rbc_data.shares),
    {_, Shards} = lists:unzip(ShardsWithSize),
    case leo_erasure:decode({Threshold, N - Threshold}, Shards, element(1, hd(ShardsWithSize))) of
        {ok, Msg} ->
            %% recompute merkle root H
            MsgSize = byte_size(Msg),
            {ok, AllShards} = leo_erasure:encode({Threshold, N - Threshold}, Msg),
            AllShardsWithSize = [{MsgSize, Shard} || Shard <- AllShards],
            Merkle = merkerl:new(AllShardsWithSize, fun merkerl:hash_value/1),
            MerkleRootHash = merkerl:root_hash(Merkle),
            case H == MerkleRootHash of
                true ->
                    %% root hashes match
                    %% check if ready already sent
                    case Data#rbc_data.ready_sent of
                        true ->
                            %% check if we have enough readies and enough echoes
                            %% N-2F echoes and 2F + 1 readies
                            case sets:size(Data#rbc_data.num_echoes) >= Threshold andalso sets:size(Data#rbc_data.num_readies) >= (2*F + 1) of
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
                    {Data#rbc_data{state=aborted}, abort}
            end;
        {error, _Reason} ->
            {Data#rbc_data{state=waiting}, ok}
    end.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

kill(Data) ->
    Data#rbc_data{state=aborted}.

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
    ok.


pid_dying_test() ->
    N = 5,
    F = 1,
    Msg = crypto:strong_rand_bytes(512),
    S0 = hbbft_rbc:init(N, F),
    S1 = hbbft_rbc:init(N, F),
    S2 = hbbft_rbc:init(N, F),
    S3 = hbbft_rbc:init(N, F),
    S4 = hbbft_rbc:init(N, F),
    {NewS0, {send, MsgsToSend}} = hbbft_rbc:input(S0, Msg),
    States = [NewS0, S1, kill(S2), S3, S4],
    StatesWithId = lists:zip(lists:seq(0, length(States) - 1), States),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(?MODULE, [{0, {send, MsgsToSend}}], StatesWithId, sets:new()),
    %% everyone but the dead node should converge
    ?assertEqual(N - 1, sets:size(ConvergedResults)),
    ok.

two_pid_dying_test() ->
    N = 5,
    F = 1,
    Msg = crypto:strong_rand_bytes(512),
    S0 = hbbft_rbc:init(N, F),
    S1 = hbbft_rbc:init(N, F),
    S2 = hbbft_rbc:init(N, F),
    S3 = hbbft_rbc:init(N, F),
    S4 = hbbft_rbc:init(N, F),
    {NewS0, {send, MsgsToSend}} = hbbft_rbc:input(S0, Msg),
    States = [NewS0, S1, kill(S2), S3, kill(S4)],
    StatesWithId = lists:zip(lists:seq(0, length(States) - 1), States),
    {_, ConvergedResults} = hbbft_test_utils:do_send_outer(?MODULE, [{0, {send, MsgsToSend}}], StatesWithId, sets:new()),
    %% nobody should converge
    ?assertEqual(0, sets:size(ConvergedResults)),
    ok.
-endif.
