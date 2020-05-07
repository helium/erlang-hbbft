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

-spec status(rbc_data()) -> map().
status(RBCData) ->
    #{state => RBCData#rbc_data.state,
      echoes => hash_key(RBCData#rbc_data.num_echoes),
      readies => hash_key(RBCData#rbc_data.num_readies),
      stripes => hash_key(maps:map(fun(_K, V) -> maps:keys(V) end, RBCData#rbc_data.stripes)),
      seen_val => RBCData#rbc_data.seen_val,
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
    {ok, Shards} = erasure:encode(K, M, Msg),
    %% Need to know the size of the msg for decoding
    Merkle = merkerl:new(Shards, fun merkerl:hash_value/1),
    MerkleRootHash = merkerl:root_hash(Merkle),
    %% gen_proof = branches for each merkle node (Hash(shard))
    BranchesForShards = [merkerl:gen_proof(Hash, Merkle) || {Hash, _} <- merkerl:leaves(Merkle)],
    %% TODO add our identity to the ready/echo sets?
    NewData = Data#rbc_data{msg=Msg},
    Result = [ {unicast, J, {val, MerkleRootHash, lists:nth(J+1, BranchesForShards), lists:nth(J+1, Shards)}} || J <- lists:seq(0, N-1)],
    %% unicast all the VAL packets and multicast the ECHO for our own share
    {NewData#rbc_data{state=waiting}, {send, Result}}; % ++ [{multicast, {echo, MerkleRootHash, hd(BranchesForShards), hd(ShardsWithSize)}}]}}.
input(_Data, _Msg) ->
    %% ignore anyone else other than leader who tries to start RBC
    ignore.


%% message handlers
-spec handle_msg(rbc_data(), non_neg_integer(), val_msg() | echo_msg() | ready_msg()) -> {rbc_data(), ok | {send, send_commands()}} | ignore |
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
-spec val(rbc_data(), non_neg_integer(), merkerl:hash(), merkerl:proof(), binary()) -> {rbc_data(), ok | {send, send_commands()}} | ignore.
val(Data = #rbc_data{seen_val=false, leader=Leader}, J, H, Bj, Sj) when J == Leader ->
    case merkerl:verify_proof(merkerl:hash_value(Sj), H, Bj) of
        ok ->
            %% the merkle proof is valid, update seen_val for this path
            {Data#rbc_data{seen_val=true}, {send, [{multicast, {echo, H, Bj, Sj}}]}};
        {error, _} ->
            %% otherwise discard
            ignore
    end;
val(#rbc_data{leader=_Leader}, _J, _H, _Bi, _Si) ->
    %% we already had a val, just ignore this
    %% also, we probably don't care about this leader's VAL message either
    ignore.

%% Figure2. Bullet3
%% upon receiving ECHO(h, bj, sj ) from party Pj ,
%% check that bj is a valid Merkle branch for root h and leaf sj ,
%% and otherwise discard
-spec echo(rbc_data(), non_neg_integer(), merkerl:hash(), merkerl:proof(), binary()) -> {rbc_data(), ok | {send, send_commands()} | {result, V :: binary()} | abort} | ignore.
echo(#rbc_data{state=done}, _J, _H, _Bj, _Sj) ->
    ignore;
echo(Data, J, H, Bj, Sj) ->
    %% check if you've already seen an ECHO from the sender
    case has_echo(Data, J) of
        true ->
            %% already got an ECHO From J, discard
            ignore;
        false ->
            case merkerl:verify_proof(merkerl:hash_value(Sj), H, Bj) of
                ok ->
                    %% valid branch
                    DataWithEchoes = add_echo(Data, H, J),
                    NewData = add_stripe(DataWithEchoes, H, J, Sj),
                    check_completion(NewData, H);
                {error, _} ->
                    %% otherwise discard
                    ignore
            end
    end.

%% Figure2. Bullet5
%% upon receiving f + 1 matching READY(h) messages, if READY
%% has not yet been sent, multicast READY(h)
-spec ready(rbc_data(), non_neg_integer(), merkerl:hash()) -> {rbc_data(), ok | {send, send_commands()} | {result, V :: binary()}} | ignore.
ready(#rbc_data{state=done}, _J, _H) ->
    ignore;
ready(Data, J, H) ->
    %% check if you've already seen this ready
    case has_ready(Data, J) of
        true ->
            ignore;
        false ->
            %% increment num_readies
            NewData = add_ready(Data, H, J),
            check_completion(NewData, H)
    end.

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

    %% Object would be encoded into {k + m} blocks, any {k} blocks could be used to decode back
    %% K: The number of data chunks - The number of chunks in which the original object is divided
    %% M: The number of coding chunks - The number of additional chunks computed by erasure's encoding functions
    M = N - 2*F, %% Note: M = Threshold (specified in RBC protocol)
    K = 2*F,

    Shards = maps:values(maps:get(H, Data#rbc_data.stripes, #{})),
    Echoes = maps:get(H, Data#rbc_data.num_echoes, []),
    Readies = maps:get(H, Data#rbc_data.num_readies, []),

    case {length(Echoes), length(Readies)} of
        {NumEchoes, NumReadies} when NumReadies >= 2*F + 1 andalso NumEchoes >= N - 2*F ->
            %% upon receiving 2f+1 matching READY(h) messages, wait for N−2f ECHO messages, then decode v
            case Data#rbc_data.msg of
                undefined ->
                    %% we didn't compute it below
                    case decode_result(K, M, Shards, H) of
                        {ok, Msg} ->
                            {Data#rbc_data{state=done}, {result, Msg}};
                        {error, hash_mismatch} ->
                            %% the protocol does not specify what to do here
                            %% but failing seems the safest course of action
                            {Data#rbc_data{state=done}, {result, aborted}};
                        {error, _} ->
                            %% likely we had some invalid shards, wait for some more
                            {Data, ok}
                    end;
                Msg ->
                    {Data#rbc_data{state=done}, {result, Msg}}
            end;
        {NumEchoes, _} when NumEchoes >= N - F andalso Data#rbc_data.ready_sent == false ->
            %% upon receiving validECHO(h,·,·) messages from N−f distinct parties,
            %% - interpolate {s′j} from any N−2f leaves received
            %% – recompute Merkle root h′and if h′ /= h then abort
            %% – if READY(h) has not yet been sent, multicast READY(h)
            case decode_result(K, M, Shards, H) of
                {ok, Msg} ->
                    {Data#rbc_data{ready_sent=true, msg=Msg}, {send, [{multicast, {ready, H}}]}};
                {error, hash_mismatch} ->
                    %% abort
                    %% may incriminate the leader
                    {Data#rbc_data{state=done}, {result, aborted}};
                {error, _} ->
                    %% likely we had some invalid shards, wait for some more
                    {Data, ok}
            end;
        {_, NumReadies} when NumReadies >= F + 1 andalso Data#rbc_data.ready_sent == false ->
            %% upon receiving f+1 matching READY(h) messages, if READY has not yet been sent, multicast READY(h)
            {Data#rbc_data{ready_sent=true}, {send, [{multicast, {ready, H}}]}};
        _ ->
            {Data, ok}
    end.

-spec insert_once(non_neg_integer(), [non_neg_integer()]) -> [non_neg_integer(), ...].
insert_once(Element, List) ->
    case lists:member(Element, List) of
        true -> List;
        false -> [Element | List]
    end.

decode_result(K, M, Shards, H) ->
    case erasure:decode(K, M, Shards) of
        {ok, Msg} ->
            %% recompute merkle root H
            {ok, AllShards} = erasure:encode(K, M, Msg),
            Merkle = merkerl:new(AllShards, fun merkerl:hash_value/1),
            MerkleRootHash = merkerl:root_hash(Merkle),
            case H == MerkleRootHash of
                true ->
                    {ok, Msg};
                false ->
                    {error, hash_mismatch}
            end;
        Error ->
            %% TODO fix erlang_erasure to return the invalid shard so we can remove it
            %% and retry if we have at least N−2f shares left. Realistically this should
            %% be very hard because the merkle hash is also over the shard metadata so
            %% any shard that gets this far is likely valid, assuming an honest leader.
            Error
    end.

hash_key(Map) ->
    Keys = maps:keys(Map),
    Len = case length(Keys) of
              N when N < 2 ->
                  6;
              _ ->
                  erlang:max(6, binary:longest_common_prefix(Keys))
          end,
    maps:fold(fun(Key, Value, Acc) ->
                      maps:put(binary:part(Key, 0, Len), Value, Acc)
              end, #{}, Map).
