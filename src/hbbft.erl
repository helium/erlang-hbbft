-module(hbbft).

-export([
    init/6, init/7,
    init/9,
    get_stamp_fun/1,
    set_stamp_fun/4,
    start_on_demand/1,
    input/2,
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
    have_key/1,
    is_serialized/1
]).

-ifdef(TEST).
-export([
    encrypt/3,
    get_encrypted_key/2,
    decrypt/2,
    encode_list/1,
    abstraction_breaking_set_acs_results/2,
    abstraction_breaking_set_enc_keys/2
]).
-endif.

-type acs_results() :: [{non_neg_integer(), binary()}].
-type enc_keys() :: #{non_neg_integer() => tc_ciphertext:ciphertext() | tpke_pubkey:ciphertext()}.

-record(hbbft_data, {
    batch_size :: pos_integer(),
    curve :: curve(),
    key_share :: key_share(),
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
            {boolean() | undefined, {non_neg_integer(), tc_decryption_share:dec_share()} | erlang_pbc:element()}
    },
    decrypted = #{} :: #{non_neg_integer() => [binary()]},
    sig_shares = #{} :: #{non_neg_integer() => {non_neg_integer(), tc_signature_share:sig_share() | erlang_pbc:element()}},
    thingtosign :: undefined | binary() | erlang_pbc:element(),
    stampfun :: undefined | {atom(), atom(), list()},
    stamps = [] :: [{non_neg_integer(), binary()}],
    failed_combine = [] :: [non_neg_integer()],
    failed_decrypt = [] :: [non_neg_integer()]
}).

-type curve() :: 'SS512' | 'BLS12-381'.
-type key_share() :: undefined | tc_key_share:tc_key_share() | tpke_privkey:privkey().
-type hbbft_data() :: #hbbft_data{}.
-type acs_msg() :: {{acs, non_neg_integer()}, hbbft_acs:msgs()}.
-type dec_msg() :: {dec, non_neg_integer(), non_neg_integer(), {non_neg_integer(), binary()}}.
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

-export_type([curve/0, key_share/0]).

-if(?OTP_RELEASE > 22).
%% Ericsson why do you hate us so?
-define(ENCRYPT(Key, IV, AAD, PlainText, TagLength),
    crypto:crypto_one_time_aead(aes_256_gcm, Key, IV, PlainText, AAD, TagLength, true)
).
-define(DECRYPT(Key, IV, AAD, CipherText, Tag),
    crypto:crypto_one_time_aead(aes_256_gcm, Key, IV, CipherText, AAD, Tag, false)
).
-else.
-define(ENCRYPT(Key, IV, AAD, PlainText, TagLength),
    crypto:block_encrypt(aes_gcm, Key, IV, {AAD, PlainText, TagLength})
).
-define(DECRYPT(Key, IV, AAD, CipherText, Tag),
    crypto:block_decrypt(aes_gcm, Key, IV, {AAD, CipherText, Tag})
).
-endif.

-spec have_key(hbbft_data()) -> boolean().
have_key(#hbbft_data{key_share = Key}) ->
    %% we don't have a key if it's undefined
    Key /= undefined.

-spec status(hbbft_data()) -> map().
status(HBBFTData) ->
    #{
        curve => HBBFTData#hbbft_data.curve,
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
    Curve = hbbft_utils:curve(KeyShare),
    #hbbft_data{
        curve = Curve,
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
        curve = Curve,
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
    EncX = encrypt(Curve, KeyShare, encode_list([Stamp|Proposed])),
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
-spec input(hbbft_data(), binary()) -> {hbbft_data(), ok | {send, [rbc_wrapped_output()]} | full}.
input(Data = #hbbft_data{buf = Buf, max_buf = MaxBuf}, Txn) when
    is_binary(Txn), length(Buf) < MaxBuf
->
    %% add this txn to the the buffer
    NewBuf = Buf ++ [Txn],
    maybe_start_acs(Data#hbbft_data{buf = NewBuf});
input(Data = #hbbft_data{buf = _Buf}, _Txn) when is_binary(_Txn) ->
    %% drop the txn
    {Data, full}.

%% The user has constructed something that looks like a block and is telling us which transactions
%% to remove from the buffer (accepted or invalid). Transactions missing causal context
%% (eg. a missing monotonic nonce prior to the current nonce) should remain in the buffer and thus
%% should not be placed in TransactionsToRemove. Once this returns, the user should call next_round/1.
-spec finalize_round(hbbft_data(), [binary()], binary()) ->
    {hbbft_data(), {send, [hbbft_utils:multicast(sign_msg())]}}.
finalize_round(Data, TransactionsToRemove, ThingToSign0) ->
    NewBuf = lists:filter(
        fun(Item) ->
            not lists:member(Item, TransactionsToRemove)
        end,
        Data#hbbft_data.buf
    ),
    {SigShare, ThingToSign} = case Data#hbbft_data.curve of
                                  'BLS12-381' ->
                                      {tc_key_share:sign_share(Data#hbbft_data.key_share, ThingToSign0), ThingToSign0};
                                  'SS512' ->
                                      HashThing = tpke_pubkey:hash_message(tpke_privkey:public_key(Data#hbbft_data.key_share), ThingToSign0),
                                      {tpke_privkey:sign(Data#hbbft_data.key_share, HashThing), HashThing}
                              end,
    BinSigShare = hbbft_utils:sig_share_to_binary(Data#hbbft_data.curve, SigShare),
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
                    {EncKey, KeyIsValid} = case Data#hbbft_data.curve of
                                               'BLS12-381' ->
                                                   EncKey0 = tc_ciphertext:deserialize(Result),
                                                   {EncKey0, tc_ciphertext:verify(EncKey0)};
                                               'SS512' ->
                                                   case get_encrypted_key(Data#hbbft_data.key_share, Result) of
                                                       {ok, EncKey0} ->
                                                           {EncKey0, true};
                                                       error ->
                                                           {nothing, false}
                                                   end
                                           end,
                    case KeyIsValid of
                        true ->
                            %% we've validated the ciphertext, this is now safe to do
                            Share = case Data#hbbft_data.curve of
                                        'BLS12-381' ->
                                            tc_key_share:decrypt_share(Data#hbbft_data.key_share, EncKey);
                                        'SS512' ->
                                            tpke_privkey:decrypt_share(Data#hbbft_data.key_share, EncKey)
                                    end,
                            SerializedShare = hbbft_utils:dec_share_to_binary(Data#hbbft_data.curve, Share),
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
                                Valid = case Data#hbbft_data.curve of
                                            'BLS12-381' ->
                                                tc_key_share:verify_decryption_share(
                                                  Data#hbbft_data.key_share,
                                                  Share,
                                                  EncKey
                                                 );
                                            'SS512' ->
                                                tpke_pubkey:verify_share(tpke_privkey:public_key(Data#hbbft_data.key_share), Share, EncKey)
                                        end,
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
handle_msg(Data = #hbbft_data{round = R, curve = Curve, key_share = SK}, J, {dec, R, I, Share}) ->
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
            DeserializedShare = hbbft_utils:binary_to_dec_share(Curve, SK, Share),
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
                                Valid = case Data#hbbft_data.curve of
                                            'BLS12-381' ->
                                                tc_key_share:verify_decryption_share(
                                                  Data#hbbft_data.key_share,
                                                  AShare,
                                                  EncKey
                                                 );
                                            'SS512' ->
                                                tpke_pubkey:verify_share(tpke_privkey:public_key(Data#hbbft_data.key_share), AShare, EncKey)
                                        end,
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
                            Data#hbbft_data.curve,
                            Data#hbbft_data.f,
                            Data#hbbft_data.key_share,
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
                        Decrypted0 ->
                            Decrypted = case Data#hbbft_data.curve of
                                'BLS12-381' ->
                                    %% the ciphertext is direct in this mode
                                    Decrypted0;
                                'SS512' ->
                                    %% we decrypted the key only
                                    {I, Enc} = lists:keyfind(I, 1, Data#hbbft_data.acs_results),
                                    decrypt(Decrypted0, Enc)
                            end,
                            case Decrypted of
                                error ->
                                    %% this only happens for SS512
                                    %% can't decrypt, consider this ACS a failure
                                    %% just declare this ACS returned an empty list because we had
                                    %% f+1 valid shares but the resulting decryption key was unusuable to decrypt
                                    %% the transaction bundle
                                    NewDecrypted = maps:put(I, [], Data#hbbft_data.decrypted),
                                    check_completion(Data#hbbft_data{dec_shares=NewShares, decrypted=NewDecrypted,
                                                                     failed_decrypt=[I|Data#hbbft_data.failed_decrypt]});
                                _ ->
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
handle_msg(Data = #hbbft_data{round = R, thingtosign = ThingToSign, curve = Curve, key_share = SK}, J, {sign, R, BinShare}) when
    ThingToSign /= undefined
->
    %% messages related to signing the final block for this round, see finalize_round for more information
    %% Note: this is an extension to the HoneyBadger BFT specification
    Share = hbbft_utils:binary_to_sig_share(Curve, SK, BinShare),
    %% verify the share
    ValidShare = case Data#hbbft_data.curve of
                     'BLS12-381' ->
                         tc_key_share:verify_signature_share(Data#hbbft_data.key_share, Share, ThingToSign);
                     'SS512' ->
                         tpke_pubkey:verify_signature_share(tpke_privkey:public_key(Data#hbbft_data.key_share), Share, ThingToSign)
                 end,
    case ValidShare of
        true ->
            NewSigShares = maps:put(J, Share, Data#hbbft_data.sig_shares),
            %% check if we have at least f+1 shares
            case maps:size(NewSigShares) > Data#hbbft_data.f andalso not Data#hbbft_data.sent_sig of
                true ->
                    %% ok, we have enough people agreeing with us we can combine the signature shares
                    {ok, Sig} = case Data#hbbft_data.curve of
                                    'BLS12-381' ->
                                        tc_key_share:combine_signature_shares(
                                          Data#hbbft_data.key_share,
                                          maps:values(NewSigShares));
                                    'SS512' ->
                                        tpke_pubkey:combine_verified_signature_shares(tpke_privkey:public_key(Data#hbbft_data.key_share), maps:values(NewSigShares))
                                end,
                    ValidSignature = case Data#hbbft_data.curve of
                                         'BLS12-381' ->
                                             tc_key_share:verify(Data#hbbft_data.key_share, Sig, ThingToSign);
                                         'SS512' ->
                                             tpke_pubkey:verify_signature(tpke_privkey:public_key(Data#hbbft_data.key_share), Sig, ThingToSign)
                                     end,
                    case ValidSignature of
                        true ->
                            SerializedSig = case Data#hbbft_data.curve of
                                                'BLS12-381' ->
                                                    tc_signature:serialize(Sig);
                                                'SS512' ->
                                                    erlang_pbc:element_to_binary(Sig)
                                            end,
                            %% verified signature, send the signature
                            {Data#hbbft_data{sig_shares = NewSigShares, sent_sig = true},
                                {result, {signature, SerializedSig}}};
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
        curve = Curve,
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
            EncX = encrypt(Curve, KeyShare, encode_list([Stamp|Proposed])),
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

-spec encrypt('SS512', tpke_pubkey:pubkey(), binary()) -> binary();
             ('BLS12-381', tc_key_share:tc_key_share(), binary()) -> binary().
encrypt('BLS12-381', SK, Bin) ->
    tc_ciphertext:serialize(tc_key_share:encrypt(SK, Bin));
encrypt('SS512', SK, Bin) ->
    PK = tpke_privkey:public_key(SK),
    %% generate a random AES key and IV
    Key = crypto:strong_rand_bytes(32),
    IV = crypto:strong_rand_bytes(16),
    %% encrypt that random AES key with the HBBFT replica set's public key
    %% the result of the encryption is a 3-tuple that contains 2 PBC Elements and a 32 byte binary
    %% we need to encode all this crap into a binary value that we can unpack again sanely
    EncryptedKey = tpke_pubkey:encrypt(PK, Key),
    EncryptedKeyBin = tpke_pubkey:ciphertext_to_binary(EncryptedKey),
    %% encrypt the bundle with AES-GCM and put the IV and the encrypted key in the Additional Authenticated Data (AAD)
    AAD = <<IV:16/binary, (byte_size(EncryptedKeyBin)):16/integer-unsigned, EncryptedKeyBin/binary>>,
    {CipherText, CipherTag} = ?ENCRYPT(Key, IV, AAD, Bin, 16),
    %% assemble a final binary packet
    <<AAD/binary, CipherTag:16/binary, CipherText/binary>>.

-spec get_encrypted_key(tpke_privkey:privkey(), binary()) -> {ok, tpke_pubkey:ciphertext()} | error.
get_encrypted_key(SK, <<_IV:16/binary, EncKeySize:16/integer-unsigned, EncKey:EncKeySize/binary, _/binary>>) ->
    PubKey = tpke_privkey:public_key(SK),
    try tpke_pubkey:binary_to_ciphertext(EncKey, PubKey) of
        CipherText ->
            {ok, CipherText}
    catch error:inconsistent_ciphertext ->
              error
    end.

-spec decrypt(binary(), binary()) -> binary() | error.
decrypt(Key, Bin) ->
    <<IV:16/binary, EncKeySize:16/integer-unsigned, EncKey:EncKeySize/binary, Tag:16/binary, CipherText/binary>> = Bin,
    ?DECRYPT(Key, IV, <<IV:16/binary, EncKeySize:16/integer-unsigned, EncKey:(EncKeySize)/binary>>, CipherText, Tag).

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
serialize(#hbbft_data{key_share = SK, curve=Curve} = Data, true) ->
    %% serialize the private key as well
    SerSK = case Curve of
        'BLS12-381' ->
            tc_key_share:serialize(SK);
        'SS512' ->
            tpke_privkey:serialize(SK)
    end,
    {serialize_hbbft_data(Data), SerSK}.

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

    Curve = hbbft_utils:curve(SK),

    EncKeys = maps:map(
                fun(_, Ciphertext) ->
                        case Curve of
                            'BLS12-381' ->
                                tc_ciphertext:deserialize(Ciphertext);
                            'SS512' ->
                                tpke_pubkey:binary_to_ciphertext(Ciphertext, tpke_privkey:public_key(SK))
                        end
                end,
                EncKeys0
               ),
    #hbbft_data{
        curve = Curve,
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
                {Valid, hbbft_utils:binary_to_dec_share(Curve, SK, Share)}
            end,
            DecShares
        ),
        sig_shares = maps:map(
            fun(_, Share) -> hbbft_utils:binary_to_sig_share(Curve, SK, Share) end,
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
    curve = Curve,
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
        enc_keys => maps:map(fun(_, Ciphertext) -> case Curve of
                                                       'BLS12-381' ->
                                                           tc_ciphertext:serialize(Ciphertext);
                                                       'SS512' ->
                                                           tpke_pubkey:ciphertext_to_binary(Ciphertext)
                                                   end
                             end, EncKeys),
        dec_shares => maps:map(
            fun(_, {Valid, Share}) -> {Valid, hbbft_utils:dec_share_to_binary(Curve, Share)} end,
            DecShares
        ),
        sig_shares => maps:map(fun(_, V) -> hbbft_utils:sig_share_to_binary(Curve, V) end, SigShares),
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
        'BLS12-381',
        pos_integer(),
        tc_key_share:tc_key_share(),
        [{non_neg_integer(), tc_decryption_share:dec_share()}],
        tc_ciphertext:ciphertext()
    ) -> undefined | binary();
    (
        'SS512',
        pos_integer(),
        tpke_privkey:privkey(),
        [{non_neg_integer(), erlang_pbc:element()}],
        erlang_pbc:element()
    ) -> undefined | binary().
combine_shares(Curve, F, SK, SharesForThisBundle, Ciphertext) ->
    %% only use valid shares so an invalid share doesn't corrupt our result
    ValidSharesForThisBundle = [S || {true, S} <- SharesForThisBundle],
    case length(ValidSharesForThisBundle) > F of
        true ->
            case Curve of
                'BLS12-381' ->
                    {ok, Bin} = tc_key_share:combine_decryption_shares(
                        SK,
                        ValidSharesForThisBundle,
                        Ciphertext
                    ),
                    Bin;
                'SS512' ->
                    tpke_pubkey:combine_shares(
                        tpke_privkey:public_key(SK),
                        Ciphertext,
                        ValidSharesForThisBundle
                    )
            end;
        false ->
            %% not enough valid shares to bother trying to combine them
            undefined
    end.

encode_list(L) ->
    encode_list(L, []).

encode_list([], Acc) ->
    list_to_binary(lists:reverse(Acc));
encode_list([H | T], Acc) ->
    Sz = byte_size(H),
    case Sz >= 16#ffffff of
        true ->
            encode_list(T, Acc);
        false ->
            encode_list(T, [<<Sz:24/integer-unsigned-little, H/binary>> | Acc])
    end.

decode_list(<<>>, Acc) ->
    lists:reverse(Acc);
decode_list(<<Length:24/integer-unsigned-little, Entry:Length/binary, Tail/binary>>, Acc) ->
    decode_list(Tail, [Entry | Acc]);
decode_list(_, _Acc) ->
    {error, bad_chunk_encoding}.
