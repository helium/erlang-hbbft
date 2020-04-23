-module(hbbft).

-export([init/6, init/7, init/9,
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
         encrypt/2,
         decrypt/2,
         handle_msg/3,
         serialize/1,
         serialize/2,
         deserialize/2,
         status/1,
         have_key/1,
         is_serialized/1]).

-ifdef(TEST).
-export([get_encrypted_key/2]).
-endif.

-record(hbbft_data, {
          batch_size :: pos_integer(),
          secret_key :: undefined | tpke_privkey:privkey(),
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
          acs_results = [] :: [{non_neg_integer(), binary()}],
          enc_keys = #{} :: #{non_neg_integer() => tpke_pubkey:ciphertext()}, %% will only ever hold verified ciphertexts
          dec_shares = #{} :: #{{non_neg_integer(), non_neg_integer()} => {boolean() | undefined, {non_neg_integer(), erlang_pbc:element()}}},
          decrypted = #{} :: #{non_neg_integer() => [binary()]},
          sig_shares = #{} :: #{non_neg_integer() => {non_neg_integer(), erlang_pbc:element()}},
          thingtosign :: undefined | erlang_pbc:element(),
          stampfun :: undefined | {atom(), atom(), list()},
          stamps = [] :: [{non_neg_integer(), binary()}],
          failed_combine = [] :: [non_neg_integer()],
          failed_decrypt = [] :: [non_neg_integer()]
         }).

-type hbbft_data() :: #hbbft_data{}.
-type acs_msg() :: {{acs, non_neg_integer()}, hbbft_acs:msgs()}.
-type dec_msg() :: {dec, non_neg_integer(), non_neg_integer(), {non_neg_integer(), binary()}}.
-type sign_msg() :: {sign, non_neg_integer(), binary()}.
-type rbc_wrapped_output() :: hbbft_utils:unicast({{acs, non_neg_integer()}, {{rbc, non_neg_integer()}, hbbft_rbc:val_msg()}}) | hbbft_utils:multicast({{acs, non_neg_integer()}, {{rbc, non_neg_integer()}, hbbft_rbc:echo_msg() | hbbft_rbc:ready_msg()}}).
-type bba_wrapped_output() :: hbbft_utils:multicast({{acs, non_neg_integer()}, hbbft_acs:bba_msg()}).

-spec have_key(hbbft_data()) -> boolean().
have_key(#hbbft_data{secret_key = Key}) ->
    %% we don't have a key if it's undefined
    Key /= undefined.

-spec status(hbbft_data()) -> map().
status(HBBFTData) ->
    #{batch_size => HBBFTData#hbbft_data.batch_size,
      buf => length(HBBFTData#hbbft_data.buf),
      max_buf => HBBFTData#hbbft_data.max_buf,
      round => HBBFTData#hbbft_data.round,
      acs_init => HBBFTData#hbbft_data.acs_init,
      acs => hbbft_acs:status(HBBFTData#hbbft_data.acs),
      sent_txns => HBBFTData#hbbft_data.sent_txns,
      sent_sig => HBBFTData#hbbft_data.sent_sig,
      acs_results => element(1, lists:unzip(HBBFTData#hbbft_data.acs_results)),
      decryption_shares => group_by(maps:keys(HBBFTData#hbbft_data.dec_shares)),
      valid_decryption_shares => group_by(maps:keys(maps:filter(fun(_, {Valid, _}) -> Valid == true end, HBBFTData#hbbft_data.dec_shares))),
      invalid_decryption_shares => group_by(maps:keys(maps:filter(fun(_, {Valid, _}) -> Valid == false end, HBBFTData#hbbft_data.dec_shares))),
      unvalidated_decryption_shares => group_by(maps:keys(maps:filter(fun(_, {Valid, _}) -> Valid == undefined end, HBBFTData#hbbft_data.dec_shares))),
      decrypted => maps:keys(HBBFTData#hbbft_data.decrypted),
      j => HBBFTData#hbbft_data.j,
      failed_combine => HBBFTData#hbbft_data.failed_combine,
      failed_decrypt => HBBFTData#hbbft_data.failed_decrypt
     }.

-spec init(tpke_privkey:privkey(), pos_integer(), non_neg_integer(), non_neg_integer(), pos_integer(), infinity | pos_integer()) -> hbbft_data().
init(SK, N, F, J, BatchSize, MaxBuf) ->
    init(SK, N, F, J, BatchSize, MaxBuf, undefined, 0, []).

-spec init(tpke_privkey:privkey(), pos_integer(), non_neg_integer(), non_neg_integer(), pos_integer(), infinity | pos_integer(), {atom(), atom(), list()}) -> hbbft_data().
init(SK, N, F, J, BatchSize, MaxBuf, {M, Fn, A}) ->
    init(SK, N, F, J, BatchSize, MaxBuf, {M, Fn, A}, 0, []).

init(SK, N, F, J, BatchSize, MaxBuf, StampFun, Round, Buf) ->
    #hbbft_data{secret_key=SK,
                n=N, f=F, j=J,
                batch_size=BatchSize,
                acs=hbbft_acs:init(SK, N, F, J),
                round = Round,
                buf = Buf,
                max_buf=MaxBuf,
                stampfun=StampFun}.


-spec get_stamp_fun(hbbft_data()) -> {atom(), atom(), list()} | undefined.
get_stamp_fun(#hbbft_data{stampfun=S}) ->
    S.

-spec set_stamp_fun(atom(), atom(), list(), hbbft_data()) -> hbbft_data().
set_stamp_fun(M, F, A, Data) when is_atom(M), is_atom(F) ->
    Data#hbbft_data{stampfun={M, F, A}}.

%% start acs on demand
-spec start_on_demand(hbbft_data()) -> {hbbft_data(), already_started | {send, [rbc_wrapped_output()]}}.
start_on_demand(Data = #hbbft_data{buf=Buf, j=J, n=N, secret_key=SK, batch_size=BatchSize, acs_init=false,
                                  stamps=Stamps, decrypted=Decrypted}) ->
    %% pick proposed whichever is lesser from batchsize/n or buffer
    Proposed = hbbft_utils:random_n(min((BatchSize div N), length(Buf)), lists:sublist(Buf, BatchSize)),
    %% encrypt x -> tpke.enc(pk, proposed)
    Stamp = case Data#hbbft_data.stampfun of
                undefined -> <<>>;
                {M, F, A} -> erlang:apply(M, F, A)
            end,
    true = is_binary(Stamp),
    EncX = encrypt(tpke_privkey:public_key(SK), encode_list([Stamp|Proposed], [])),
    %% time to kick off a round
    {NewACSState, {send, ACSResponse}} = hbbft_acs:input(Data#hbbft_data.acs, EncX),
    %% add this to acs set in data and send out the ACS response(s)
    %%
    %% Also, store our own proposal and stamp so we can avoid combining/decrypting it
    %% later if it gets included in the ACS result
    {Data#hbbft_data{acs=NewACSState, acs_init=true,
                     stamps=lists:keystore(J, 1, Stamps, {J, Stamp}),
                     decrypted=maps:put(J, Proposed, Decrypted)},
     {send, hbbft_utils:wrap({acs, Data#hbbft_data.round}, ACSResponse)}};
start_on_demand(Data) ->
    {Data, already_started}.

%% someone submitting a transaction to the replica set
-spec input(hbbft_data(), binary()) -> {hbbft_data(), ok | {send, [rbc_wrapped_output()]} | full}.
input(Data = #hbbft_data{buf=Buf, max_buf=MaxBuf}, Txn) when is_binary(Txn), length(Buf) < MaxBuf->
    %% add this txn to the the buffer
    NewBuf = Buf ++ [Txn],
    maybe_start_acs(Data#hbbft_data{buf=NewBuf});
input(Data = #hbbft_data{buf=_Buf}, _Txn) when is_binary(_Txn) ->
    %% drop the txn
    {Data, full}.

%% The user has constructed something that looks like a block and is telling us which transactions
%% to remove from the buffer (accepted or invalid). Transactions missing causal context
%% (eg. a missing monotonic nonce prior to the current nonce) should remain in the buffer and thus
%% should not be placed in TransactionsToRemove. Once this returns, the user should call next_round/1.
-spec finalize_round(hbbft_data(), [binary()], binary()) -> {hbbft_data(), {send, [hbbft_utils:multicast(sign_msg())]}}.
finalize_round(Data, TransactionsToRemove, ThingToSign) ->
    NewBuf = lists:filter(fun(Item) ->
                                  not lists:member(Item, TransactionsToRemove)
                          end, Data#hbbft_data.buf),
    HashThing = tpke_pubkey:hash_message(tpke_privkey:public_key(Data#hbbft_data.secret_key), ThingToSign),
    BinShare = hbbft_utils:share_to_binary(tpke_privkey:sign(Data#hbbft_data.secret_key, HashThing)),
    %% multicast the signature to everyone
    {Data#hbbft_data{thingtosign=HashThing, buf=NewBuf}, {send, [{multicast, {sign, Data#hbbft_data.round, BinShare}}]}}.

%% does not require a signed message
-spec finalize_round(hbbft_data(), [binary()])-> hbbft_data().
finalize_round(Data, TransactionsToRemove) ->
    NewBuf = lists:filter(fun(Item) ->
                                  not lists:member(Item, TransactionsToRemove)
                          end, Data#hbbft_data.buf),
    Data#hbbft_data{buf=NewBuf}.

%% The user has obtained a signature and is ready to go to the next round
-spec next_round(hbbft_data()) -> {hbbft_data(), ok | {send, []}}.
next_round(Data = #hbbft_data{secret_key=SK, n=N, f=F, j=J}) ->
    %% reset all the round-dependant bits of the state and increment the round
    NewData = Data#hbbft_data{round=Data#hbbft_data.round + 1, acs=hbbft_acs:init(SK, N, F, J),
                              acs_init=false, acs_results=[],
                              sent_txns=false, sent_sig=false, enc_keys=#{},
                              dec_shares=#{}, decrypted=#{},
                              failed_combine=[], failed_decrypt=[],
                              sig_shares=#{}, thingtosign=undefined, stamps=[]},
    maybe_start_acs(NewData).

-spec next_round(hbbft_data(), pos_integer(), [binary()]) -> {hbbft_data(), ok | {send, []}}.
next_round(Data = #hbbft_data{secret_key=SK, n=N, f=F, j=J, buf=Buf}, NextRound, TransactionsToRemove) ->
    %% remove the request transactions
    NewBuf = lists:filter(fun(Item) ->
                                  not lists:member(Item, TransactionsToRemove)
                          end, Buf),
    %% reset all the round-dependant bits of the state and increment the round
    NewData = Data#hbbft_data{round=NextRound, acs=hbbft_acs:init(SK, N, F, J),
                              acs_init=false, acs_results=[],
                              sent_txns=false, sent_sig=false, enc_keys=#{},
                              dec_shares=#{}, decrypted=#{}, buf=NewBuf,
                              failed_combine=[], failed_decrypt=[],
                              sig_shares=#{}, thingtosign=undefined, stamps=[]},
    maybe_start_acs(NewData).

-spec round(hbbft_data()) -> non_neg_integer().
round(_Data=#hbbft_data{round=Round}) ->
    Round.

-spec buf(hbbft_data()) -> [any()].
buf(_Data=#hbbft_data{buf = Buf}) ->
    Buf.

-spec buf([binary()], hbbft_data()) -> hbbft_data().
buf(Buf, Data) ->
    Data#hbbft_data{buf=Buf}.

-spec handle_msg(hbbft_data(), non_neg_integer(), acs_msg() | dec_msg() | sign_msg()) -> {hbbft_data(), ok |
                                                                                          defer |
                                                                                          {send, [hbbft_utils:multicast(dec_msg() |
                                                                                                                        sign_msg()) |
                                                                                                  rbc_wrapped_output() |
                                                                                                  bba_wrapped_output()]} |
                                                                                          {result, {transactions, list(), [binary()]}} |
                                                                                          {result, {signature, binary()}}} | ignore.
handle_msg(Data = #hbbft_data{round=R}, _J, {{acs, R2}, _ACSMsg}) when R2 > R ->
    %% ACS requested we defer this message for now
    {Data, defer};
handle_msg(Data = #hbbft_data{round=R}, J, {{acs, R}, ACSMsg}) ->
    %% ACS message for this round
    case hbbft_acs:handle_msg(Data#hbbft_data.acs, J, ACSMsg) of
        ignore -> ignore;
        {NewACS, ok} ->
            {Data#hbbft_data{acs=NewACS}, ok};
        {NewACS, {send, ACSResponse}} ->
            {Data#hbbft_data{acs=NewACS}, {send, hbbft_utils:wrap({acs, Data#hbbft_data.round}, ACSResponse)}};
        {NewACS, {result_and_send, Results0, {send, ACSResponse}}} ->
            %% ACS[r] has returned, time to move on to the decrypt phase
            %% start decrypt phase
            {Replies, Results, EncKeys} = lists:foldl(fun({I, Result}, {RepliesAcc, ResultsAcc, EncKeysAcc}=Acc) ->
                                        %% this function will validate the ciphertext is consistent with our key
                                        case get_encrypted_key(Data#hbbft_data.secret_key, Result) of
                                            {ok, EncKey} ->
                                                %% we've validated the ciphertext, this is now safe to do
                                                Share = tpke_privkey:decrypt_share(Data#hbbft_data.secret_key, EncKey),
                                                SerializedShare = hbbft_utils:share_to_binary(Share),
                                                {[{multicast, {dec, Data#hbbft_data.round, I, SerializedShare}}|RepliesAcc], [{I, Result}|ResultsAcc], maps:put(I, EncKey, EncKeysAcc)};
                                            error ->
                                                %% invalid ciphertext, we should not proceed with this result
                                                Acc
                                        end
                             end, {[], [], #{}}, Results0),
            %% verify any shares we received before we got the ACS result
            %%
            %% check if we have a copy of our own proposal. this will always be true
            %% unless we did an upgrade in the middle of a round. we can remove this check
            %% later
            HasOwnProposal = maps:is_key(J, Data#hbbft_data.decrypted),
            VerifiedShares = maps:map(fun({I, _}, {undefined, Share}) when
                                                %% don't verify if this is our own proposal and we have a copy of it
                                                not (I == J andalso HasOwnProposal)  ->
                                              case maps:find(I, EncKeys) of
                                                  {ok, EncKey} ->
                                                      Valid = tpke_pubkey:verify_share(tpke_privkey:public_key(Data#hbbft_data.secret_key), Share, EncKey),
                                                      {Valid, Share};
                                                  error ->
                                                      %% this is a share for an RBC we will never decode
                                                      {undefined, Share}
                                              end;
                                         (_, V) ->
                                              V
                                      end, Data#hbbft_data.dec_shares),
            %% if we are not in the ACS result set, filter out our own results
            {ResultIndices, _} = lists:unzip(Results),
            Decrypted = maps:with(ResultIndices, Data#hbbft_data.decrypted),
            Stamps = lists:filter(fun({I, _Stamp}) ->
                                          lists:member(I, ResultIndices)
                                  end, Data#hbbft_data.stamps),
            {Data#hbbft_data{acs=NewACS, acs_results=Results, dec_shares=VerifiedShares, decrypted=Decrypted, stamps=Stamps, enc_keys=EncKeys},
             {send,  hbbft_utils:wrap({acs, Data#hbbft_data.round}, ACSResponse) ++ Replies}};
        {NewACS, defer} ->
            {Data#hbbft_data{acs=NewACS}, defer}
    end;
handle_msg(Data = #hbbft_data{round=R}, _J, {dec, R2, _I, _Share}) when R2 > R ->
    {Data, defer};
handle_msg(Data = #hbbft_data{round=R}, J, {dec, R, I, Share}) ->
    %% check if we have enough to decode the bundle
    case maps:is_key(I, Data#hbbft_data.decrypted) %% have we already decrypted for this instance?
        orelse maps:is_key({I, J}, Data#hbbft_data.dec_shares) of %% do we already have this share?
        true ->
            %% we already have this share, or we've already decrypted this ACS result
            %% we don't need this
            ignore;
        false ->
            %% the Share now is a binary, deserialize it and then store in the dec_shares map
            DeserializedShare = hbbft_utils:binary_to_share(Share, tpke_privkey:public_key(Data#hbbft_data.secret_key)),
            %% add share to map and validate any previously unvalidated shares
            %%
            %% check if we have a copy of our own proposal. this will always be true
            %% unless we did an upgrade in the middle of a round. we can remove this check
            %% later
            HasOwnProposal = maps:is_key(J, Data#hbbft_data.decrypted),
            NewShares = maps:map(fun({I1, _}, {undefined, AShare}) when
                                           %% don't verify if this is our own proposal and we have a copy of it
                                           not (I1 == J andalso HasOwnProposal) ->
                                              case maps:find(I1, Data#hbbft_data.enc_keys) of
                                                  {ok, EncKey} ->
                                                      %% we validated the ciphertext above so we don't need to re-check it here
                                                      Valid = tpke_pubkey:verify_share(tpke_privkey:public_key(Data#hbbft_data.secret_key), AShare, EncKey),
                                                      {Valid, AShare};
                                                  error ->
                                                      %% this is a share for an RBC we will never decode
                                                      {undefined, AShare}
                                              end;
                                         (_, V) ->
                                              V
                                      end, maps:put({I, J}, {undefined, DeserializedShare}, Data#hbbft_data.dec_shares)),
            SharesForThisBundle = [ S || {{Idx, _}, S} <- maps:to_list(NewShares), I == Idx],
            case lists:keymember(I, 1, Data#hbbft_data.acs_results)         %% was this instance included in the ACS result set?
                 andalso maps:is_key(I, Data#hbbft_data.enc_keys)           %% do we have a valid ciphertext
                 andalso length(SharesForThisBundle) > Data#hbbft_data.f of %% do we have f+1 decryption shares?
                true ->
                    EncKey = maps:get(I, Data#hbbft_data.enc_keys),
                    case combine_shares(Data#hbbft_data.f, Data#hbbft_data.secret_key, SharesForThisBundle, EncKey) of
                        undefined ->
                            %% can't recover the key, consider this ACS failed if we have 2f+1 shares and still can't recover the key
                            case length(SharesForThisBundle) > 2 * Data#hbbft_data.f of
                                true ->
                                    %% ok, just declare this ACS returned an empty list
                                    NewDecrypted = maps:put(I, [], Data#hbbft_data.decrypted),
                                    check_completion(Data#hbbft_data{dec_shares=NewShares, decrypted=NewDecrypted,
                                                                    failed_combine=[I|Data#hbbft_data.failed_combine]});
                                false ->
                                    {Data#hbbft_data{dec_shares=NewShares}, ok}
                            end;
                        DecKey ->
                            {I, Enc} = lists:keyfind(I, 1, Data#hbbft_data.acs_results),
                            case decrypt(DecKey, Enc) of
                                error ->
                                    %% can't decrypt, consider this ACS a failure
                                    %% just declare this ACS returned an empty list because we had
                                    %% f+1 valid shares but the resulting decryption key was unusuable to decrypt
                                    %% the transaction bundle
                                    NewDecrypted = maps:put(I, [], Data#hbbft_data.decrypted),
                                    check_completion(Data#hbbft_data{dec_shares=NewShares, decrypted=NewDecrypted,
                                                                    failed_decrypt=[I|Data#hbbft_data.failed_decrypt]});
                                Decrypted ->
                                    [Stamp | Transactions] = decode_list(Decrypted, []),
                                    NewDecrypted = maps:put(I, Transactions, Data#hbbft_data.decrypted),
                                    Stamps = [{I, Stamp} | Data#hbbft_data.stamps],
                                    check_completion(Data#hbbft_data{dec_shares=NewShares, decrypted=NewDecrypted, stamps=Stamps})
                            end
                    end;
                false ->
                    %% not enough shares yet
                    {Data#hbbft_data{dec_shares=NewShares}, ok}
            end
    end;
handle_msg(Data = #hbbft_data{round=R, thingtosign=ThingToSign}, _J, {sign, R2, _BinShare}) when ThingToSign == undefined  orelse R2 > R ->
    {Data, defer};
handle_msg(Data = #hbbft_data{round=R, thingtosign=ThingToSign}, J, {sign, R, BinShare}) when ThingToSign /= undefined ->
    %% messages related to signing the final block for this round, see finalize_round for more information
    %% Note: this is an extension to the HoneyBadger BFT specification
    Share = hbbft_utils:binary_to_share(BinShare, tpke_privkey:public_key(Data#hbbft_data.secret_key)),
    %% verify the share
    PubKey = tpke_privkey:public_key(Data#hbbft_data.secret_key),
    case tpke_pubkey:verify_signature_share(PubKey, Share, ThingToSign) of
        true ->
            NewSigShares = maps:put(J, Share, Data#hbbft_data.sig_shares),
            %% check if we have at least f+1 shares
            case maps:size(NewSigShares) > Data#hbbft_data.f andalso not Data#hbbft_data.sent_sig of
                true ->
                    %% ok, we have enough people agreeing with us we can combine the signature shares
                    {ok, Sig} = tpke_pubkey:combine_verified_signature_shares(PubKey, maps:values(NewSigShares)),
                    case tpke_pubkey:verify_signature(PubKey, Sig, ThingToSign) of
                        true ->
                            %% verified signature, send the signature
                            {Data#hbbft_data{sig_shares=NewSigShares, sent_sig=true}, {result, {signature, erlang_pbc:element_to_binary(Sig)}}};
                        false ->
                            %% must have duplicate signature shares, keep waiting
                            {Data#hbbft_data{sig_shares=NewSigShares}, ok}
                    end;
                false ->
                    {Data#hbbft_data{sig_shares=NewSigShares}, ok}
            end;
        false ->
            ignore
    end;
handle_msg(_Data, _J, _Msg) ->
    ignore.

-spec maybe_start_acs(hbbft_data()) -> {hbbft_data(), ok | {send, [rbc_wrapped_output()]}}.
maybe_start_acs(Data = #hbbft_data{n=N, j=J, secret_key=SK, batch_size=BatchSize,
                                  decrypted=Decrypted, stamps=Stamps}) ->
    case length(Data#hbbft_data.buf) > BatchSize andalso Data#hbbft_data.acs_init == false of
        true ->
            %% compose a transaction bundle
            %% get the top b elements from buf
            %% pick a random B/N selection of them
            Proposed = hbbft_utils:random_n(BatchSize div N, lists:sublist(Data#hbbft_data.buf, length(Data#hbbft_data.buf) - BatchSize + 1, BatchSize)),
            %% encrypt x -> tpke.enc(pk, proposed)
            Stamp = case Data#hbbft_data.stampfun of
                undefined -> <<>>;
                {M, F, A} -> erlang:apply(M, F, A)
            end,
            true = is_binary(Stamp),
            EncX = encrypt(tpke_privkey:public_key(SK), encode_list([Stamp|Proposed], [])),
            %% time to kick off a round
            {NewACSState, {send, ACSResponse}} = hbbft_acs:input(Data#hbbft_data.acs, EncX),
            %% add this to acs set in data and send out the ACS response(s)
            %%
            %% Also, store our own proposal and stamp so we can avoid combining/decrypting it
            %% later if it gets included in the ACS result
            {Data#hbbft_data{acs=NewACSState, acs_init=true, stamps=lists:keystore(J, 1, Stamps, {J, Stamp}),
                             decrypted=maps:put(J, Proposed, Decrypted)},
             {send, hbbft_utils:wrap({acs, Data#hbbft_data.round}, ACSResponse)}};
        false ->
            %% not enough transactions for this round yet
            {Data, ok}
    end.

-spec encrypt(tpke_pubkey:pubkey(), binary()) -> binary().
encrypt(PK, Bin) ->
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
    {CipherText, CipherTag} = crypto:block_encrypt(aes_gcm, Key, IV, {AAD, Bin}),
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
    crypto:block_decrypt(aes_gcm, Key, IV, {<<IV:16/binary, EncKeySize:16/integer-unsigned, EncKey:(EncKeySize)/binary>>, CipherText, Tag}).

-spec serialize(hbbft_data()) -> {#{atom() => binary() | map()},
                                  tpke_privkey:privkey_serialized() | tpke_privkey:privkey()}.
serialize(Data) ->
    %% serialize the SK unless explicitly told not to
    serialize(Data, true).

-spec serialize(hbbft_data(), boolean()) -> {#{atom() => binary() | map()},
                                             tpke_privkey:privkey_serialized() | tpke_privkey:privkey()}.
serialize(#hbbft_data{secret_key=SK}=Data, false) ->
    %% dont serialize the private key
    {serialize_hbbft_data(Data), SK};
serialize(#hbbft_data{secret_key=SK}=Data, true) ->
    %% serialize the private key as well
    {serialize_hbbft_data(Data), tpke_privkey:serialize(SK)}.

-spec deserialize(#{atom() => binary() | map()}, tpke_privkey:privkey()) -> hbbft_data().
deserialize(M0, SK) ->
    M = maps:map(fun(acs, V) -> V;
                (_K, V) -> binary_to_term(V)
                 end, M0),
    #{batch_size := BatchSize,
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
      stamps := Stamps} = M,

    NewThingToSign = case ThingToSign of
                         undefined -> undefined;
                         _ -> tpke_pubkey:deserialize_element(tpke_privkey:public_key(SK), ThingToSign)
                     end,
    EncKeys = case maps:find(enc_keys, M) of
                  {ok, EncKeys0} ->
                      maps:map(fun(_, Ciphertext) -> tpke_pubkey:binary_to_ciphertext(Ciphertext, tpke_privkey:public_key(SK)) end, EncKeys0);
                  error ->
                      %% upgrade from not having keys in state
                      lists:foldl(fun({I, Res}, Acc) ->
                                          %% this function will validate the ciphertext is consistent with our key
                                          case get_encrypted_key(SK, Res) of
                                              {ok, EncKey} ->
                                                  maps:put(I, EncKey, Acc);
                                              error ->
                                                  Acc
                                          end
                                  end, #{}, ACSResults)
              end,


    #hbbft_data{secret_key=SK,
                batch_size=BatchSize,
                n=N,
                f=F,
                j=J,
                round=Round,
                buf=[],
                max_buf=MaxBuf,
                acs=hbbft_acs:deserialize(ACSData, SK),
                acs_init=ACSInit,
                sent_txns=SentTxns,
                sent_sig=SentSig,
                acs_results=ACSResults,
                decrypted=Decrypted,
                enc_keys=EncKeys,
                dec_shares=maps:map(fun(_, {Valid, Share}) ->
                                            {Valid, hbbft_utils:binary_to_share(Share, tpke_privkey:public_key(SK))}
                                    end, DecShares),
                sig_shares=maps:map(fun(_, Share) -> hbbft_utils:binary_to_share(Share, tpke_privkey:public_key(SK)) end, SigShares),
                thingtosign=NewThingToSign,
                failed_combine=maps:get(failed_combine, M, []),
                failed_decrypt=maps:get(failed_decrypt, M, []),
                stampfun=Stampfun,
                stamps=Stamps}.

-spec serialize_hbbft_data(hbbft_data()) -> #{atom() => binary() | map()}.
serialize_hbbft_data(#hbbft_data{batch_size=BatchSize,
                                 n=N,
                                 f=F,
                                 j=J,
                                 round=Round,
                                 max_buf=MaxBuf,
                                 acs=ACSData,
                                 acs_init=ACSInit,
                                 sent_txns=SentTxns,
                                 sent_sig=SentSig,
                                 acs_results=ACSResults,
                                 enc_keys=EncKeys,
                                 dec_shares=DecShares,
                                 sig_shares=SigShares,
                                 decrypted=Decrypted,
                                 thingtosign=ThingToSign,
                                 failed_combine=FailedCombine,
                                 failed_decrypt=FailedDecrypt,
                                 stampfun=Stampfun,
                                 stamps=Stamps}) ->

    NewThingToSign = case ThingToSign of
                         undefined -> undefined;
                         _ -> erlang_pbc:element_to_binary(ThingToSign)
                     end,

    M = #{batch_size => BatchSize,
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
          enc_keys => maps:map(fun(_, Ciphertext) -> tpke_pubkey:ciphertext_to_binary(Ciphertext) end, EncKeys),
          dec_shares => maps:map(fun(_, {Valid, Share}) -> {Valid, hbbft_utils:share_to_binary(Share)} end, DecShares),
          sig_shares => maps:map(fun(_, V) -> hbbft_utils:share_to_binary(V) end, SigShares),
          thingtosign => NewThingToSign,
          failed_combine => FailedCombine,
          failed_decrypt => FailedDecrypt,
          stampfun => Stampfun,
          stamps => Stamps},
    maps:map(fun(acs, V) -> V;
                (_K, V) -> term_to_binary(V, [compressed])
             end, M).

-spec is_serialized(hbbft_data() | #{atom() => binary() | map()}) -> boolean().
is_serialized(Data) when is_map(Data) -> true;
is_serialized(Data) when is_record(Data, hbbft_data) -> false.

group_by(Tuples) ->
    group_by(Tuples, dict:new()).

group_by([], D) ->
    lists:keysort(1, [{K, lists:sort(V)} || {K, V} <- dict:to_list(D)]);
group_by([{K, V}|T], D) ->
    group_by(T, dict:append(K, V, D)).

check_completion(Data) ->
    case maps:size(Data#hbbft_data.decrypted) == length(Data#hbbft_data.acs_results) andalso not Data#hbbft_data.sent_txns of
        true ->
            %% we did it!
            %% Combine all unique messages into a single list
            TransactionsThisRound = lists:usort(lists:flatten(maps:values(Data#hbbft_data.decrypted))),
            StampsThisRound = lists:usort(Data#hbbft_data.stamps),
            %% return the transactions we agreed on to the user
            %% we have no idea which transactions are valid, invalid, out of order or missing
            %% causal context (eg. a nonce is not monotonic) so we return them to the user to let them
            %% figure it out. We expect the user to call finalize_round/3 once they've decided what they want to accept
            %% from this set of transactions.
            {Data#hbbft_data{sent_txns=true}, {result, {transactions, StampsThisRound, TransactionsThisRound}}};
        false ->
            {Data, ok}
    end.

-spec combine_shares(pos_integer(), tpke_privkey:privkey(), [tpke_privkey:share()], tpke_pubkey:ciphertext()) -> undefined | binary().
combine_shares(F, SK, SharesForThisBundle, EncKey) ->
    %% only use valid shares so an invalid share doesn't corrupt our result
    ValidSharesForThisBundle = [ S || {true, S} <- SharesForThisBundle ],
    case length(ValidSharesForThisBundle) > F of
        true ->
            tpke_pubkey:combine_shares(tpke_privkey:public_key(SK), EncKey, ValidSharesForThisBundle);
        false ->
            %% not enough valid shares to bother trying to combine them
            undefined
    end.

encode_list([], Acc) ->
    list_to_binary(lists:reverse(Acc));
encode_list([H|T], Acc) ->
    encode_list(T, [<<(byte_size(H)):16/integer-unsigned-little, H/binary>> | Acc]).

decode_list(<<>>, Acc) ->
    lists:reverse(Acc);
decode_list(<<Length:16/integer-unsigned-little, Entry:Length/binary, Tail/binary>>, Acc) ->
    decode_list(Tail, [Entry|Acc]).
