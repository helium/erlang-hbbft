-module(hbbft).

-export([
    init/6, init/7,
    init/9,
    get_stamp_fun/1,
    set_stamp_fun/4,
    start_on_demand/1,
    input/2,
    input/3,
    finalize_round/3,
    finalize_round/2,
    next_round/1,
    next_round/3,
    round/1,
    buf/1, buf/2,
    handle_msg/3,
    serialize/1,
    serialize/2,
    deserialize/2,
    status/1,
    is_serialized/1
]).

-ifdef(TEST).
-export([
    encrypt/2,
    encode_list/1,
    abstraction_breaking_set_acs_results/2,
    abstraction_breaking_set_enc_keys/2
]).
-endif.

-type acs_results() :: [{non_neg_integer(), binary()}].
-type enc_keys() :: #{non_neg_integer() => tc_ciphertext:ciphertext()}.

-record(hbbft_data, {
    batch_size :: pos_integer(),
    key_share :: tc_key_share:tc_key_share(),
    n :: pos_integer(),
    f :: pos_integer(),
    j :: non_neg_integer(),
    round = 0 :: non_neg_integer(),
    buf = [] :: [binary()],
    max_buf = infinity :: infinity | pos_integer(),
    acs :: hbbft_acs:acs_data(),
    acs_init = false :: boolean(),
    sent_txns = false :: boolean(),
    sent_sig = false :: boolean(),
    acs_results = [] :: acs_results(),
    %% will only ever hold verified ciphertexts
    enc_keys = #{} :: enc_keys(),
    dec_shares = #{} :: #{
        {non_neg_integer(), non_neg_integer()} =>
            {boolean() | undefined, {non_neg_integer(), tc_decryption_share:dec_share()}}
    },
    decrypted = #{} :: #{non_neg_integer() => [binary()]},
    sig_shares = #{} :: #{non_neg_integer() => {non_neg_integer(), tc_signature_share:sig_share()}},
    thingtosign :: undefined | binary(),
    stampfun :: undefined | {atom(), atom(), list()},
    stamps = [] :: [{non_neg_integer(), binary()}],
    failed_combine = [] :: [non_neg_integer()],
    failed_decrypt = [] :: [non_neg_integer()]
}).

-type hbbft_data() :: #hbbft_data{}.
-type acs_msg() :: {{acs, non_neg_integer()}, hbbft_acs:msgs()}.
-type dec_msg() :: {dec, Round :: non_neg_integer(), ActorID :: non_neg_integer(), SerializedShare :: binary()}.
-type sign_msg() :: {sign, non_neg_integer(), binary()}.
-type rbc_wrapped_output() ::
    hbbft_utils:unicast({{acs, non_neg_integer()}, {{rbc, non_neg_integer()}, hbbft_rbc:val_msg()}})
    | hbbft_utils:multicast(
        {{acs, non_neg_integer()},
            {{rbc, non_neg_integer()}, hbbft_rbc:echo_msg() | hbbft_rbc:ready_msg()}}
    ).
-type bba_wrapped_output() :: hbbft_utils:multicast(
    {{acs, non_neg_integer()}, hbbft_acs:bba_msg()}
).

-spec status(hbbft_data()) -> map().
status(HBBFTData) ->
    #{
        batch_size => HBBFTData#hbbft_data.batch_size,
        buf => length(HBBFTData#hbbft_data.buf),
        max_buf => HBBFTData#hbbft_data.max_buf,
        round => HBBFTData#hbbft_data.round,
        acs_init => HBBFTData#hbbft_data.acs_init,
        acs => hbbft_acs:status(HBBFTData#hbbft_data.acs),
        sent_txns => HBBFTData#hbbft_data.sent_txns,
        sent_sig => HBBFTData#hbbft_data.sent_sig,
        acs_results => element(1, lists:unzip(HBBFTData#hbbft_data.acs_results)),
        decryption_shares => group_by(maps:keys(HBBFTData#hbbft_data.dec_shares)),
        valid_decryption_shares => group_by(
            maps:keys(
                maps:filter(
                    fun(_, {Valid, _}) -> Valid == true end,
                    HBBFTData#hbbft_data.dec_shares
                )
            )
        ),
        invalid_decryption_shares => group_by(
            maps:keys(
                maps:filter(
                    fun(_, {Valid, _}) -> Valid == false end,
                    HBBFTData#hbbft_data.dec_shares
                )
            )
        ),
        unvalidated_decryption_shares => group_by(
            maps:keys(
                maps:filter(
                    fun(_, {Valid, _}) -> Valid == undefined end,
                    HBBFTData#hbbft_data.dec_shares
                )
            )
        ),
        decrypted => maps:keys(HBBFTData#hbbft_data.decrypted),
        j => HBBFTData#hbbft_data.j,
        failed_combine => HBBFTData#hbbft_data.failed_combine,
        failed_decrypt => HBBFTData#hbbft_data.failed_decrypt
    }.

-spec init(
    tc_key_share:tc_key_share(),
    pos_integer(),
    non_neg_integer(),
    non_neg_integer(),
    pos_integer(),
    infinity | pos_integer()
) -> hbbft_data().
init(KeyShare, N, F, J, BatchSize, MaxBuf) ->
    init(KeyShare, N, F, J, BatchSize, MaxBuf, undefined, 0, []).

-spec init(
    tc_key_share:tc_key_share(),
    pos_integer(),
    non_neg_integer(),
    non_neg_integer(),
    pos_integer(),
    infinity | pos_integer(),
    {atom(), atom(), list()}
) -> hbbft_data().
init(KeyShare, N, F, J, BatchSize, MaxBuf, {M, Fn, A}) ->
    init(KeyShare, N, F, J, BatchSize, MaxBuf, {M, Fn, A}, 0, []).

init(KeyShare, N, F, J, BatchSize, MaxBuf, StampFun, Round, Buf) ->
    #hbbft_data{
        key_share = KeyShare,
        n = N,
        f = F,
        j = J,
        batch_size = BatchSize,
        acs = hbbft_acs:init(KeyShare, N, F, J),
        round = Round,
        buf = Buf,
        max_buf = MaxBuf,
        stampfun = StampFun
    }.

-ifdef(TEST).
-spec abstraction_breaking_set_acs_results(State, acs_results()) -> State when
    State :: hbbft_data().
abstraction_breaking_set_acs_results(State, AcsResults) ->
    State#hbbft_data{acs_results = AcsResults}.

-spec abstraction_breaking_set_enc_keys(State, enc_keys()) -> State when State :: hbbft_data().
abstraction_breaking_set_enc_keys(State, EncKeys) ->
    State#hbbft_data{enc_keys = EncKeys}.
-endif.

-spec get_stamp_fun(hbbft_data()) -> {atom(), atom(), list()} | undefined.
get_stamp_fun(#hbbft_data{stampfun = S}) ->
    S.

-spec set_stamp_fun(atom(), atom(), list(), hbbft_data()) -> hbbft_data().
set_stamp_fun(M, F, A, Data) when is_atom(M), is_atom(F) ->
    Data#hbbft_data{stampfun = {M, F, A}}.

%% start acs on demand
-spec start_on_demand(hbbft_data()) ->
    {hbbft_data(), already_started | {send, [rbc_wrapped_output()]}}.
start_on_demand(
    Data = #hbbft_data{
        buf = Buf,
        j = J,
        n = N,
        key_share = KeyShare,
        batch_size = BatchSize,
        acs_init = false,
        stamps = Stamps,
        decrypted = Decrypted
    }
) ->
    %% pick proposed whichever is lesser from batchsize/n or buffer
    Proposed = hbbft_utils:random_n(
        min((BatchSize div N), length(Buf)),
        lists:sublist(Buf, BatchSize)
    ),
    Stamp =
        case Data#hbbft_data.stampfun of
            undefined -> <<>>;
            {M, F, A} -> erlang:apply(M, F, A)
        end,
    true = is_binary(Stamp),
    EncX = encrypt(KeyShare, encode_list([Stamp|Proposed])),
    %% time to kick off a round
    {NewACSState, {send, ACSResponse}} = hbbft_acs:input(Data#hbbft_data.acs, EncX),
    %% add this to acs set in data and send out the ACS response(s)
    %%
    %% Also, store our own proposal and stamp so we can avoid combining/decrypting it
    %% later if it gets included in the ACS result
    {Data#hbbft_data{
            acs = NewACSState,
            acs_init = true,
            stamps = lists:keystore(J, 1, Stamps, {J, Stamp}),
            decrypted = maps:put(J, Proposed, Decrypted)
        },
        {send, hbbft_utils:wrap({acs, Data#hbbft_data.round}, ACSResponse)}};
start_on_demand(Data) ->
    {Data, already_started}.

%% someone submitting a transaction to the replica set
-spec input(hbbft_data(), binary()) ->
    {hbbft_data(), Next}
    when
        Next
            :: {result, {Pos, BufSiz}}
            |  {result_and_send, {Pos, BufSiz}, {send, Msg}}
            |  full,
        Msg :: [rbc_wrapped_output()],
        Pos :: non_neg_integer(),
        BufSiz :: non_neg_integer().
input(Data, Txn) ->
    %% use a default function that will cause an append
    input(Data, Txn, fun(_) -> false end).

%% someone submitting a transaction to the replica set
-spec input(hbbft_data(), binary(), fun((binary()) -> boolean()) ) ->
    {hbbft_data(), Next}
    when
        Next
            :: {result, {Pos, BufSiz}}
            |  {result_and_send, {Pos, BufSiz}, {send, Msg}}
            |  full,
        Msg :: [rbc_wrapped_output()],
        Pos :: non_neg_integer(),
        BufSiz :: non_neg_integer().
input(Data = #hbbft_data{buf = Buf, max_buf = MaxBuf}, <<Txn/binary>>, InsertComparator)
    when length(Buf) < MaxBuf
->
    %% add txn to buffer
    {NewBuf, Position} = add_to_buffer(Buf, Txn, InsertComparator),
    case maybe_start_acs(Data#hbbft_data{buf = NewBuf}) of
        {NewData, ok} ->
            {NewData, {result, {Position, length(NewBuf)}}};
        {NewData, {send, Msg}} ->
            {NewData, {result_and_send, {Position, length(NewBuf)}, {send, Msg}}}
    end;
input(Data = #hbbft_data{buf = _}, <<_/binary>>, _) ->
    %% drop the txn
    {Data, full}.

%% The user has constructed something that looks like a block and is telling us which transactions
%% to remove from the buffer (accepted or invalid). Transactions missing causal context
%% (eg. a missing monotonic nonce prior to the current nonce) should remain in the buffer and thus
%% should not be placed in TransactionsToRemove. Once this returns, the user should call next_round/1.
-spec finalize_round(hbbft_data(), [binary()], binary()) ->
    {hbbft_data(), {send, [hbbft_utils:multicast(sign_msg())]}}.
finalize_round(#hbbft_data{}=Data, TransactionsToRemove, ThingToSign) ->
    NewBuf = lists:filter(
        fun(Item) ->
            not lists:member(Item, TransactionsToRemove)
        end,
        Data#hbbft_data.buf
    ),
    SigShare = tc_key_share:sign_share(Data#hbbft_data.key_share, ThingToSign),
    BinSigShare = hbbft_utils:sig_share_to_binary(SigShare),
    %% multicast the signature to everyone
    {Data#hbbft_data{thingtosign = ThingToSign, buf = NewBuf},
        {send, [{multicast, {sign, Data#hbbft_data.round, BinSigShare}}]}}.

%% does not require a signed message
-spec finalize_round(hbbft_data(), [binary()]) -> hbbft_data().
finalize_round(Data, TransactionsToRemove) ->
    NewBuf = lists:filter(
        fun(Item) ->
            not lists:member(Item, TransactionsToRemove)
        end,
        Data#hbbft_data.buf
    ),
    Data#hbbft_data{buf = NewBuf}.

%% The user has obtained a signature and is ready to go to the next round
-spec next_round(hbbft_data()) -> {hbbft_data(), ok | {send, []}}.
next_round(Data = #hbbft_data{key_share = KeyShare, n = N, f = F, j = J}) ->
    %% reset all the round-dependant bits of the state and increment the round
    NewData = Data#hbbft_data{
        round = Data#hbbft_data.round + 1,
        acs = hbbft_acs:init(KeyShare, N, F, J),
        acs_init = false,
        acs_results = [],
        sent_txns = false,
        sent_sig = false,
        enc_keys = #{},
        dec_shares = #{},
        decrypted = #{},
        failed_combine = [],
        failed_decrypt = [],
        sig_shares = #{},
        thingtosign = undefined,
        stamps = []
    },
    maybe_start_acs(NewData).

-spec next_round(hbbft_data(), pos_integer(), [binary()]) -> {hbbft_data(), ok | {send, []}}.
next_round(
    Data = #hbbft_data{key_share = KeyShare, n = N, f = F, j = J, buf = Buf},
    NextRound,
    TransactionsToRemove
) ->
    %% remove the request transactions
    NewBuf = lists:filter(
        fun(Item) ->
            not lists:member(Item, TransactionsToRemove)
        end,
        Buf
    ),
    %% reset all the round-dependant bits of the state and increment the round
    NewData = Data#hbbft_data{
        round = NextRound,
        acs = hbbft_acs:init(KeyShare, N, F, J),
        acs_init = false,
        acs_results = [],
        sent_txns = false,
        sent_sig = false,
        enc_keys = #{},
        dec_shares = #{},
        decrypted = #{},
        buf = NewBuf,
        failed_combine = [],
        failed_decrypt = [],
        sig_shares = #{},
        thingtosign = undefined,
        stamps = []
    },
    maybe_start_acs(NewData).

-spec round(hbbft_data()) -> non_neg_integer().
round(_Data = #hbbft_data{round = Round}) ->
    Round.

-spec buf(hbbft_data()) -> [any()].
buf(_Data = #hbbft_data{buf = Buf}) ->
    Buf.

-spec buf([binary()], hbbft_data()) -> hbbft_data().
buf(Buf, Data) ->
    Data#hbbft_data{buf = Buf}.

-spec handle_msg(State, J :: non_neg_integer(), Msg) -> {State, Next} | ignore when
    State :: hbbft_data(),
    Msg :: acs_msg() | dec_msg() | sign_msg(),
    Next ::
        ok
        | defer
        | {send, [NextMsg]}
        | {result, Result},
    NextMsg ::
        hbbft_utils:multicast(dec_msg() | sign_msg())
        | rbc_wrapped_output()
        | bba_wrapped_output(),
    Result ::
        {signature, binary()}
        | {transactions, list(), [binary()]}.
handle_msg(Data = #hbbft_data{round = R}, _J, {{acs, R2}, _ACSMsg}) when R2 > R ->
    %% ACS requested we defer this message for now
    {Data, defer};
handle_msg(Data = #hbbft_data{round = R}, J, {{acs, R}, ACSMsg}) ->
    %% ACS message for this round
    case hbbft_acs:handle_msg(Data#hbbft_data.acs, J, ACSMsg) of
        ignore ->
            ignore;
        {NewACS, ok} ->
            {Data#hbbft_data{acs = NewACS}, ok};
        {NewACS, {send, ACSResponse}} ->
            {Data#hbbft_data{acs = NewACS},
                {send, hbbft_utils:wrap({acs, Data#hbbft_data.round}, ACSResponse)}};
        {NewACS, {result_and_send, Results0, {send, ACSResponse}}} ->
            %% ACS[r] has returned, time to move on to the decrypt phase
            %% start decrypt phase
            {Replies, Results, EncKeys} = lists:foldl(
                fun({I, Result}, {RepliesAcc, ResultsAcc, EncKeysAcc} = Acc) ->
                    %% this function will validate the ciphertext is consistent with our key
                    EncKey = tc_ciphertext:deserialize(Result),
                    case tc_ciphertext:verify(EncKey) of
                        true ->
                            %% we've validated the ciphertext, this is now safe to do
                            Share = tc_key_share:decrypt_share(Data#hbbft_data.key_share, EncKey),
                            SerializedShare = hbbft_utils:dec_share_to_binary(Share),
                            {[
                                    {multicast, {dec, Data#hbbft_data.round, I, SerializedShare}}
                                    | RepliesAcc
                                ],
                                [{I, Result} | ResultsAcc], maps:put(I, EncKey, EncKeysAcc)};
                        false ->
                            %% invalid ciphertext, we should not proceed with this result
                            Acc
                    end
                end,
                {[], [], #{}},
                Results0
            ),
            %% verify any shares we received before we got the ACS result
            %%
            %% check if we have a copy of our own proposal. this will always be true
            %% unless we did an upgrade in the middle of a round. we can remove this check
            %% later
            HasOwnProposal = maps:is_key(J, Data#hbbft_data.decrypted),
            VerifiedShares = maps:map(
                fun
                    ({I, _}, {undefined, Share}) when
                        %% don't verify if this is our own proposal and we have a copy of it
                        not (I == J andalso HasOwnProposal)
                    ->
                        case maps:find(I, EncKeys) of
                            {ok, EncKey} ->
                                Valid =
                                    tc_key_share:verify_decryption_share(
                                        Data#hbbft_data.key_share,
                                        Share,
                                        EncKey
                                    ),
                                {Valid, Share};
                            error ->
                                %% this is a share for an RBC we will never decode
                                {undefined, Share}
                        end;
                    (_, V) ->
                        V
                end,
                Data#hbbft_data.dec_shares
            ),
            %% if we are not in the ACS result set, filter out our own results
            {ResultIndices, _} = lists:unzip(Results),
            Decrypted = maps:with(ResultIndices, Data#hbbft_data.decrypted),
            Stamps = lists:filter(
                fun({I, _Stamp}) ->
                    lists:member(I, ResultIndices)
                end,
                Data#hbbft_data.stamps
            ),
            {Data#hbbft_data{
                    acs = NewACS,
                    acs_results = Results,
                    dec_shares = VerifiedShares,
                    decrypted = Decrypted,
                    stamps = Stamps,
                    enc_keys = EncKeys
                },
                {send, hbbft_utils:wrap({acs, Data#hbbft_data.round}, ACSResponse) ++ Replies}};
        {NewACS, defer} ->
            {Data#hbbft_data{acs = NewACS}, defer}
    end;
handle_msg(Data = #hbbft_data{round = R}, _J, {dec, R2, _I, _Share}) when R2 > R ->
    {Data, defer};
handle_msg(Data = #hbbft_data{round = R, key_share = SK}, J, {dec, R, I, Share}) ->
    %% check if we have enough to decode the bundle

    %% have we already decrypted for this instance?
    case
        maps:is_key(I, Data#hbbft_data.decrypted) orelse
            %% do we already have this share?
            maps:is_key({I, J}, Data#hbbft_data.dec_shares)
    of
        true ->
            %% we already have this share, or we've already decrypted this ACS result
            %% we don't need this
            ignore;
        false ->
            %% the Share now is a binary, deserialize it and then store in the dec_shares map
            DeserializedShare = hbbft_utils:binary_to_dec_share(Share),
            %% add share to map and validate any previously unvalidated shares
            %%
            %% check if we have a copy of our own proposal. this will always be true
            %% unless we did an upgrade in the middle of a round. we can remove this check
            %% later
            HasOwnProposal = maps:is_key(J, Data#hbbft_data.decrypted),
            NewShares = maps:map(
                fun
                    ({I1, _}, {undefined, AShare}) when
                        %% don't verify if this is our own proposal and we have a copy of it
                        not (I1 == J andalso HasOwnProposal)
                    ->
                        case maps:find(I1, Data#hbbft_data.enc_keys) of
                            {ok, EncKey} ->
                                %% we validated the ciphertext above so we don't need to re-check it here
                                Valid =
                                    tc_key_share:verify_decryption_share(
                                        SK,
                                        AShare,
                                        EncKey
                                     ),
                                {Valid, AShare};
                            error ->
                                %% this is a share for an RBC we will never decode
                                {undefined, AShare}
                        end;
                    (_, V) ->
                        V
                end,
                maps:put({I, J}, {undefined, DeserializedShare}, Data#hbbft_data.dec_shares)
            ),
            SharesForThisBundle = [S || {{Idx, _}, S} <- maps:to_list(NewShares), I == Idx],
            %% was this instance included in the ACS result set?
            case
                lists:keymember(I, 1, Data#hbbft_data.acs_results) andalso
                    %% do we have a valid ciphertext
                    maps:is_key(I, Data#hbbft_data.enc_keys) andalso
                    %% do we have f+1 decryption shares?
                    length(SharesForThisBundle) > Data#hbbft_data.f
            of
                true ->
                    EncKey = maps:get(I, Data#hbbft_data.enc_keys),
                    case
                        combine_shares(
                            Data#hbbft_data.f,
                            SK,
                            SharesForThisBundle,
                            EncKey
                        )
                    of
                        undefined ->
                            %% can't recover the key, consider this ACS failed if we have 2f+1 shares and still can't recover the key
                            case length(SharesForThisBundle) > 2 * Data#hbbft_data.f of
                                true ->
                                    %% ok, just declare this ACS returned an empty list
                                    NewDecrypted = maps:put(I, [], Data#hbbft_data.decrypted),
                                    check_completion(Data#hbbft_data{
                                        dec_shares = NewShares,
                                        decrypted = NewDecrypted,
                                        failed_combine = [I | Data#hbbft_data.failed_combine]
                                    });
                                false ->
                                    {Data#hbbft_data{dec_shares = NewShares}, ok}
                            end;
                        Decrypted ->
                            #hbbft_data{batch_size = B, n = N} = Data,
                            case decode_list(Decrypted, []) of
                                [_Stamp | Transactions] when length(Transactions) > (B div N) ->
                                    % Batch exceeds agreed-upon size.
                                    % Ignoring this proposal.
                                    check_completion(
                                      Data#hbbft_data{
                                        dec_shares =
                                        NewShares,
                                        decrypted =
                                        maps:put(I, [], Data#hbbft_data.decrypted)
                                       }
                                     );
                                [Stamp | Transactions] ->
                                    NewDecrypted = maps:put(
                                                     I,
                                                     Transactions,
                                                     Data#hbbft_data.decrypted
                                                    ),
                                    Stamps = [{I, Stamp} | Data#hbbft_data.stamps],
                                    check_completion(Data#hbbft_data{
                                                       dec_shares = NewShares,
                                                       decrypted = NewDecrypted,
                                                       stamps = Stamps
                                                      });
                                {error, _} ->
                                    %% this is an invalid proposal. Because the shares are verifiable
                                    %% we know that everyone will fail to decrypt so we declare this as an empty share,
                                    %% as in the decryption failure case above, and continue
                                    %% TODO track failed decodes like we track failed decrypts
                                    NewDecrypted = maps:put(I, [], Data#hbbft_data.decrypted),
                                    check_completion(Data#hbbft_data{
                                                       dec_shares = NewShares,
                                                       decrypted = NewDecrypted
                                                      })
                            end
                    end;
                false ->
                    %% not enough shares yet
                    {Data#hbbft_data{dec_shares = NewShares}, ok}
            end
    end;
handle_msg(Data = #hbbft_data{round = R, thingtosign = ThingToSign}, _J, {sign, R2, _BinShare}) when
    ThingToSign == undefined orelse R2 > R
->
    {Data, defer};
handle_msg(Data = #hbbft_data{round = R, thingtosign = ThingToSign, key_share = SK}, J, {sign, R, BinShare}) when
    ThingToSign /= undefined
->
    %% messages related to signing the final block for this round, see finalize_round for more information
    %% Note: this is an extension to the HoneyBadger BFT specification
    Share = hbbft_utils:binary_to_sig_share(BinShare),
    %% verify the share
    case
        tc_key_share:verify_signature_share(
            SK,
            Share,
            ThingToSign
        )
    of
        true ->
            NewSigShares = maps:put(J, Share, Data#hbbft_data.sig_shares),
            %% check if we have at least f+1 shares
            case maps:size(NewSigShares) > Data#hbbft_data.f andalso not Data#hbbft_data.sent_sig of
                true ->
                    %% ok, we have enough people agreeing with us we can combine the signature shares
                    {ok, Sig} =
                        tc_key_share:combine_signature_shares(
                            SK,
                            maps:values(NewSigShares)
                        ),
                    ValidSignature =
                        tc_key_share:verify(
                            SK,
                            Sig,
                            ThingToSign
                        ),
                    case ValidSignature of
                        true ->
                            %% verified signature, send the signature
                            {Data#hbbft_data{sig_shares = NewSigShares, sent_sig = true},
                                {result, {signature, tc_signature:serialize(Sig)}}};
                        false ->
                            %% must have duplicate signature shares, keep waiting
                            {Data#hbbft_data{sig_shares = NewSigShares}, ok}
                    end;
                false ->
                    {Data#hbbft_data{sig_shares = NewSigShares}, ok}
            end;
        false ->
            ignore
    end;
handle_msg(_Data, _J, _Msg) ->
    % TODO Consider either crashing or returning {ok, _} | {error, _} result.
    ignore.

-spec maybe_start_acs(hbbft_data()) -> {hbbft_data(), ok | {send, [rbc_wrapped_output()]}}.
maybe_start_acs(
    Data = #hbbft_data{
        n = N,
        j = J,
        key_share = KeyShare,
        batch_size = BatchSize,
        decrypted = Decrypted,
        stamps = Stamps
    }
) ->
    case length(Data#hbbft_data.buf) > BatchSize andalso Data#hbbft_data.acs_init == false of
        true ->
            %% compose a transaction bundle
            %% get the top b elements from buf
            %% pick a random B/N selection of them
            Proposed = hbbft_utils:random_n(
                BatchSize div N,
                lists:sublist(
                    Data#hbbft_data.buf,
                    length(Data#hbbft_data.buf) - BatchSize + 1,
                    BatchSize
                )
            ),
            Stamp =
                case Data#hbbft_data.stampfun of
                    undefined -> <<>>;
                    {M, F, A} -> erlang:apply(M, F, A)
                end,
            true = is_binary(Stamp),
            EncX = encrypt(KeyShare, encode_list([Stamp|Proposed])),
            %% time to kick off a round
            {NewACSState, {send, ACSResponse}} = hbbft_acs:input(Data#hbbft_data.acs, EncX),
            %% add this to acs set in data and send out the ACS response(s)
            %%
            %% Also, store our own proposal and stamp so we can avoid combining/decrypting it
            %% later if it gets included in the ACS result
            {Data#hbbft_data{
                    acs = NewACSState,
                    acs_init = true,
                    stamps = lists:keystore(J, 1, Stamps, {J, Stamp}),
                    decrypted = maps:put(J, Proposed, Decrypted)
                },
                {send, hbbft_utils:wrap({acs, Data#hbbft_data.round}, ACSResponse)}};
        false ->
            %% not enough transactions for this round yet
            {Data, ok}
    end.

-spec encrypt(tc_key_share:tc_key_share(), binary()) -> binary().
encrypt(SK, Bin) ->
    tc_ciphertext:serialize(tc_key_share:encrypt(SK, Bin)).

-spec serialize(hbbft_data()) ->
    {#{atom() => binary() | map()}, binary() | tc_key_share:tc_key_share()}.
serialize(Data) ->
    %% serialize the SK unless explicitly told not to
    serialize(Data, true).

-spec serialize(hbbft_data(), boolean()) ->
    {#{atom() => binary() | map()}, binary() | tc_key_share:tc_key_share()}.
serialize(#hbbft_data{key_share = SK} = Data, false) ->
    %% dont serialize the private key
    {serialize_hbbft_data(Data), SK};
serialize(#hbbft_data{key_share = SK} = Data, true) ->
    %% serialize the private key as well
    {serialize_hbbft_data(Data), tc_key_share:serialize(SK)}.

-spec deserialize(#{atom() => binary() | map()}, tc_key_share:tc_key_share()) -> hbbft_data().
deserialize(M0, SK) ->
    M = maps:map(
        fun
            (acs, V) -> V;
            (_K, V) -> binary_to_term(V)
        end,
        M0
    ),
    #{
        batch_size := BatchSize,
        n := N,
        f := F,
        j := J,
        round := Round,
        max_buf := MaxBuf,
        acs := ACSData,
        acs_init := ACSInit,
        sent_txns := SentTxns,
        sent_sig := SentSig,
        acs_results := ACSResults,
        decrypted := Decrypted,
        sig_shares := SigShares,
        dec_shares := DecShares,
        thingtosign := ThingToSign,
        stampfun := Stampfun,
        stamps := Stamps,
        enc_keys := EncKeys0
    } = M,
    EncKeys = maps:map(
                fun(_, Ciphertext) -> tc_ciphertext:deserialize(Ciphertext) end,
                EncKeys0
               ),
    #hbbft_data{
        key_share = SK,
        batch_size = BatchSize,
        n = N,
        f = F,
        j = J,
        round = Round,
        buf = [],
        max_buf = MaxBuf,
        acs = hbbft_acs:deserialize(ACSData, SK),
        acs_init = ACSInit,
        sent_txns = SentTxns,
        sent_sig = SentSig,
        acs_results = ACSResults,
        decrypted = Decrypted,
        enc_keys = EncKeys,
        dec_shares = maps:map(
            fun(_, {Valid, Share}) ->
                {Valid, hbbft_utils:binary_to_dec_share(Share)}
            end,
            DecShares
        ),
        sig_shares = maps:map(
            fun(_, Share) -> hbbft_utils:binary_to_sig_share(Share) end,
            SigShares
        ),
        thingtosign = ThingToSign,
        failed_combine = maps:get(failed_combine, M, []),
        failed_decrypt = maps:get(failed_decrypt, M, []),
        stampfun = Stampfun,
        stamps = Stamps
    }.

-spec serialize_hbbft_data(hbbft_data()) -> #{atom() => binary() | map()}.
serialize_hbbft_data(#hbbft_data{
    batch_size = BatchSize,
    n = N,
    f = F,
    j = J,
    round = Round,
    max_buf = MaxBuf,
    acs = ACSData,
    acs_init = ACSInit,
    sent_txns = SentTxns,
    sent_sig = SentSig,
    acs_results = ACSResults,
    enc_keys = EncKeys,
    dec_shares = DecShares,
    sig_shares = SigShares,
    decrypted = Decrypted,
    thingtosign = ThingToSign,
    failed_combine = FailedCombine,
    failed_decrypt = FailedDecrypt,
    stampfun = Stampfun,
    stamps = Stamps
}) ->
    M = #{
        batch_size => BatchSize,
        n => N,
        f => F,
        round => Round,
        max_buf => MaxBuf,
        acs => hbbft_acs:serialize(ACSData),
        acs_init => ACSInit,
        sent_txns => SentTxns,
        decrypted => Decrypted,
        j => J,
        sent_sig => SentSig,
        acs_results => ACSResults,
        enc_keys => maps:map(fun(_, Ciphertext) -> tc_ciphertext:serialize(Ciphertext) end, EncKeys),
        dec_shares => maps:map(
            fun(_, {Valid, Share}) -> {Valid, hbbft_utils:dec_share_to_binary(Share)} end,
            DecShares
        ),
        sig_shares => maps:map(fun(_, V) -> hbbft_utils:sig_share_to_binary(V) end, SigShares),
        thingtosign => ThingToSign,
        failed_combine => FailedCombine,
        failed_decrypt => FailedDecrypt,
        stampfun => Stampfun,
        stamps => Stamps
    },
    maps:map(
        fun
            (acs, V) -> V;
            (_K, V) -> term_to_binary(V, [compressed])
        end,
        M
    ).

-spec is_serialized(hbbft_data() | #{atom() => binary() | map()}) -> boolean().
is_serialized(Data) when is_map(Data) -> true;
is_serialized(Data) when is_record(Data, hbbft_data) -> false.

group_by(Tuples) ->
    group_by(Tuples, dict:new()).

group_by([], D) ->
    lists:keysort(1, [{K, lists:sort(V)} || {K, V} <- dict:to_list(D)]);
group_by([{K, V} | T], D) ->
    group_by(T, dict:append(K, V, D)).

check_completion(Data) ->
    case
        maps:size(Data#hbbft_data.decrypted) == length(Data#hbbft_data.acs_results) andalso
            not Data#hbbft_data.sent_txns
    of
        true ->
            %% we did it!
            %% Combine all unique messages into a single list
            TransactionsThisRound = lists:usort(
                lists:flatten(maps:values(Data#hbbft_data.decrypted))
            ),
            StampsThisRound = lists:usort(Data#hbbft_data.stamps),
            %% return the transactions we agreed on to the user
            %% we have no idea which transactions are valid, invalid, out of order or missing
            %% causal context (eg. a nonce is not monotonic) so we return them to the user to let them
            %% figure it out. We expect the user to call finalize_round/3 once they've decided what they want to accept
            %% from this set of transactions.
            {Data#hbbft_data{sent_txns = true},
                {result, {transactions, StampsThisRound, TransactionsThisRound}}};
        false ->
            {Data, ok}
    end.

-spec combine_shares
    (
        pos_integer(),
        tc_key_share:tc_key_share(),
        [{non_neg_integer(), tc_decryption_share:dec_share()}],
        tc_ciphertext:ciphertext()
    ) -> undefined | binary().
combine_shares(F, SK, SharesForThisBundle, Ciphertext) ->
    %% only use valid shares so an invalid share doesn't corrupt our result
    ValidSharesForThisBundle = [S || {true, S} <- SharesForThisBundle],
    case length(ValidSharesForThisBundle) > F of
        true ->
            {ok, Bin} = tc_key_share:combine_decryption_shares(
                SK,
                ValidSharesForThisBundle,
                Ciphertext
            ),
            Bin;
        false ->
            %% not enough valid shares to bother trying to combine them
            undefined
    end.

encode_list(L) ->
    %% 1MB hard limit for proposal
    encode_list(L, 1*1024*1024, []).

encode_list([], _, Acc) ->
    list_to_binary(lists:reverse(Acc));
encode_list([H | T], Count, Acc) ->
    Sz = byte_size(H),
    case Sz >= 16#ffffff orelse (Count - Sz) =< 0 of
        true ->
            encode_list(T, Count, Acc);
        false ->
            encode_list(T, Count - Sz, [<<Sz:24/integer-unsigned-little, H/binary>> | Acc])
    end.

decode_list(<<>>, Acc) ->
    lists:reverse(Acc);
decode_list(<<Length:24/integer-unsigned-little, Entry:Length/binary, Tail/binary>>, Acc) ->
    decode_list(Tail, [Entry | Acc]);
decode_list(_, _Acc) ->
    {error, bad_chunk_encoding}.

-spec add_to_buffer([A], A, fun((A) -> boolean())) -> {[A], non_neg_integer()}.
add_to_buffer(Buffer, Element, InsertComparator) ->
    add_to_buffer(lists:reverse(Buffer), [], Element, InsertComparator).

add_to_buffer([], Passed, Element, _InsertComparator) ->
    {[Element | Passed], 1};
add_to_buffer([Head|Buffer], Passed, Element, InsertComparator) ->
    case InsertComparator(Head) of
        false ->
            add_to_buffer(Buffer, [Head|Passed], Element, InsertComparator);
        true ->
            {lists:reverse(Buffer) ++ [Head, Element | Passed], length(Buffer) + 2}
    end.


-ifdef(TEST).

-include_lib("eunit/include/eunit.hrl").

buf_insert_test_() ->
    [
        ?_assertMatch({[0], 1}, add_to_buffer([], 0, fun(_) -> true end)),
        ?_assertMatch({[0], 1}, add_to_buffer([], 0, fun(_) -> false end)),

        ?_assertMatch({[0, 1], 1}, add_to_buffer([1], 0, fun(X) -> X < 1 end)),
        ?_assertMatch({[0, 1], 1}, add_to_buffer([1], 0, fun(X) -> X > 1 end)),
        ?_assertMatch({[1, 0], 2}, add_to_buffer([1], 0, fun(X) -> X =:= 1 end)),
        ?_assertMatch({[1, 0], 2}, add_to_buffer([1], 0, fun(X) -> X =< 1 end)),
        ?_assertMatch({[1, 0], 2}, add_to_buffer([1], 0, fun(X) -> X >= 1 end)),

        ?_assertMatch({[1, 2, 3, 5, 0], 5}, add_to_buffer([1, 2, 3, 5], 0, fun(X) -> X < 6 end)),
        ?_assertMatch({[1, 2, 3, 0, 5], 4}, add_to_buffer([1, 2, 3, 5], 0, fun(X) -> X < 5 end)),
        ?_assertMatch({[1, 2, 0, 3, 5], 3}, add_to_buffer([1, 2, 3, 5], 0, fun(X) -> X < 3 end)),
        ?_assertMatch({[1, 0, 2, 3, 5], 2}, add_to_buffer([1, 2, 3, 5], 0, fun(X) -> X < 2 end)),
        ?_assertMatch({[0, 1, 2, 3, 5], 1}, add_to_buffer([1, 2, 3, 5], 0, fun(X) -> X < 1 end))
    ].

-endif.
