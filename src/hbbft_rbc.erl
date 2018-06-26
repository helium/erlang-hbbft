-module(hbbft_rbc).

-export([init/4, input/2, handle_msg/3, status/1]).

-record(rbc_data, {
          state = init :: init | waiting | done,
          %% each rbc actor must know its identity
          pid :: non_neg_integer(),
          %% each rbc actor must know who the leader is
          %% this would be used for determining who broadcasts the VAL message
          leader :: non_neg_integer(),
          n :: pos_integer(),
          f :: non_neg_integer(),
          msg = undefined :: binary() | undefined,
          num_echoes = #{} :: #{merkerl:hash() => [non_neg_integer()]},
          num_readies = #{} :: #{merkerl:hash() => [non_neg_integer()]},
          seen_val = false :: boolean(),
          ready_sent = false :: boolean(),
          %% roothash: #{sender: {size, shard}}
          stripes = #{} :: #{merkerl:hash() => #{non_neg_integer() => {pos_integer(), binary()}}}
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

status(RBCData) ->
    #{state => RBCData#rbc_data.state,
      num_echoes => length(maps:values(RBCData#rbc_data.num_echoes)),
      num_readies => length(maps:values(RBCData#rbc_data.num_readies)),
      ready_sent => RBCData#rbc_data.ready_sent,
      leader => RBCData#rbc_data.leader
     }.

-spec init(pos_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer()) -> rbc_data().
init(N, F, Pid, Leader) ->
    #rbc_data{n=N, f=F, pid=Pid, leader=Leader}.

%% Figure2. Bullet1
%% let {Sj} j∈[N] be the blocks of an (N − 2 f , N)-erasure coding
%% scheme applied to v
%% let h be a Merkle tree root computed over {Sj}
%% send VAL(h, b j , s j ) to each party P j , where b j is the jth
%% Merkle tree branch
-spec input(rbc_data(), binary()) -> {rbc_data(), {send, send_commands()}}.
input(Data = #rbc_data{state=init, n=N, f=F, pid=Pid, leader=Leader}, Msg) when Pid == Leader->
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
    NewData = Data#rbc_data{msg=Msg},
    Result = [ {unicast, J, {val, MerkleRootHash, lists:nth(J+1, BranchesForShards), lists:nth(J+1, ShardsWithSize)}} || J <- lists:seq(0, N-1)],
    %% unicast all the VAL packets and multicast the ECHO for our own share
    {NewData#rbc_data{state=waiting}, {send, Result}}; % ++ [{multicast, {echo, MerkleRootHash, hd(BranchesForShards), hd(ShardsWithSize)}}]}}.
input(Data, _Msg) ->
    %% ignore anyone else other than leader who tries to start RBC
    {Data, ok}.


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
%% only multicast ECHO when VAL msssage is from the known leader
-spec val(rbc_data(), non_neg_integer(), merkerl:hash(), merkerl:proof(), binary()) -> {rbc_data(), ok | {send, send_commands()}}.
val(Data = #rbc_data{seen_val=false, leader=Leader}, J, H, Bj, Sj) when J == Leader ->
    case merkerl:verify_proof(merkerl:hash_value(Sj), H, Bj) of
        ok ->
            %% the merkle proof is valid, update seen_val for this path
            {Data#rbc_data{seen_val=true}, {send, [{multicast, {echo, H, Bj, Sj}}]}};
        {error, _} ->
            %% otherwise discard
            {Data, ok}
    end;
val(Data=#rbc_data{leader=_Leader}, _J, _H, _Bi, _Si) ->
    %% we already had a val, just ignore this
    %% also, we probably don't care about this leader's VAL message either
    {Data, ok}.

%% Figure2. Bullet3
%% upon receiving ECHO(h, bj, sj ) from party Pj ,
%% check that bj is a valid Merkle branch for root h and leaf sj ,
%% and otherwise discard
-spec echo(rbc_data(), non_neg_integer(), merkerl:hash(), merkerl:proof(), binary()) -> {rbc_data(), ok | {send, send_commands()} | {result, V :: binary()} | abort}.
echo(Data = #rbc_data{state=done}, _J, _H, _Bj, _Sj) ->
    {Data, ok};
echo(Data = #rbc_data{n=N, f=F}, J, H, Bj, Sj) ->

    %% check if you've already seen an ECHO from the sender
    case has_echo(Data, J) of
        true ->
            %% already got an ECHO From J, discard
            {Data, ok};
        false ->
            case merkerl:verify_proof(merkerl:hash_value(Sj), H, Bj) of
                ok ->
                    %% valid branch
                    DataWithEchoes = add_echo(Data, H, J),
                    NewData = add_stripe(DataWithEchoes, H, J, Sj),
                    case length(maps:get(H, NewData#rbc_data.num_echoes, [])) >= (N - F) andalso maps:size(maps:get(H, NewData#rbc_data.stripes, [])) >= (N - 2*F) of
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
            end
    end.

%% Figure2. Bullet5
%% upon receiving f + 1 matching READY(h) messages, if READY
%% has not yet been sent, multicast READY(h)
-spec ready(rbc_data(), non_neg_integer(), merkerl:hash()) -> {rbc_data(), ok | {send, send_commands()} | {result, V :: binary()}}.
ready(Data = #rbc_data{state=waiting, n=N, f=F}, J, H) ->
    %% increment num_readies

    %% check if you've already seen this ready
    case has_ready(Data, J) of
        true ->
            {Data, ok};
        false ->
            NewData = add_ready(Data, H, J),
            case length(maps:get(H, NewData#rbc_data.num_readies, [])) >= F + 1 andalso maps:size(maps:get(H, NewData#rbc_data.stripes, [])) >= (N - 2*F) of
                true ->
                    check_completion(NewData, H);
                false ->
                    %% waiting
                    {NewData, ok}
            end
    end;

ready(Data, _J, _H) ->
    {Data, ok}.


%% helper functions
-spec add_stripe(rbc_data(), merkerl:hash(), non_neg_integer(), binary()) -> rbc_data().
add_stripe(Data = #rbc_data{stripes=Stripes}, RootHash, Sender, Shard) ->
    %% who sent these stripes
    ValuesForRootHash = maps:get(RootHash, Stripes, #{}),
    %% add the sender who sent the shard
    NewMap = maps:put(Sender, Shard, ValuesForRootHash),
    Data#rbc_data{stripes = maps:put(RootHash, NewMap, Stripes)}.

-spec add_echo(rbc_data(), merkerl:hash(), non_neg_integer()) -> rbc_data().
add_echo(Data = #rbc_data{num_echoes = Echoes}, RootHash, Sender) ->
    EchoesForThisHash = maps:get(RootHash, Echoes, []),
    Data#rbc_data{num_echoes = maps:put(RootHash, insert_once(Sender, EchoesForThisHash), Echoes)}.

-spec add_ready(rbc_data(), merkerl:hash(), non_neg_integer()) -> rbc_data().
add_ready(Data = #rbc_data{num_readies = Readies}, RootHash, Sender) ->
    ReadiesForThisHash = maps:get(RootHash, Readies, []),
    Data#rbc_data{num_readies = maps:put(RootHash, insert_once(Sender, ReadiesForThisHash), Readies)}.

-spec has_echo(rbc_data(), non_neg_integer()) -> boolean().
has_echo(_Data = #rbc_data{num_echoes = Echoes}, Sender) ->
    lists:any(fun(L) -> lists:member(Sender, L) end, maps:values(Echoes)).

-spec has_ready(rbc_data(), non_neg_integer()) -> boolean().
has_ready(_Data = #rbc_data{num_readies = Readies}, Sender) ->
    lists:any(fun(L) -> lists:member(Sender, L) end, maps:values(Readies)).

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

    ShardsWithSize = maps:values(maps:get(H, Data#rbc_data.stripes, [])),
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
                            case length(maps:get(H, Data#rbc_data.num_echoes, [])) >= M andalso length(maps:get(H, Data#rbc_data.num_readies, [])) >= (2*F + 1) of
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
                    %% may incriminate the leader
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
