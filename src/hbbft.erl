-module(hbbft). %% big kahuna

-export([init/4, input/2, finalize_round/3, next_round/1, get_encrypted_key/2, decrypt/2, handle_msg/3]).

-record(hbbft_data, {
          secret_key :: tpke_privkey:privkey(),
          n :: pos_integer(),
          f :: pos_integer(),
          j :: non_neg_integer(),
          round = 0 :: non_neg_integer(),
          buf = queue:new() :: queue:queue(),
          acs :: hbbft_acs:acs_data(),
          acs_init = false :: boolean(),
          sent_txns = false :: boolean(),
          sent_sig = false :: boolean(),
          acs_results = [] :: [{non_neg_integer(), binary()}],
          dec_shares = #{} :: #{non_neg_integer() => {non_neg_integer(), erlang_pbc:element()}},
          decrypted = #{} :: #{non_neg_integer() => [binary()]},
          sig_shares = #{} :: #{non_neg_integer() => {non_neg_integer(), erlang_pbc:element()}},
          thingtosign :: undefined | erlang_pbc:element()
         }).

-define(BATCH_SIZE, 20).

-type hbbft_data() :: #hbbft_data{}.
-type acs_msg() :: {{acs, non_neg_integer()}, hbbft_acs:msgs()}.
-type dec_msg() :: {dec, non_neg_integer(), non_neg_integer(), {non_neg_integer(), binary()}}.
-type sign_msg() :: {sign, non_neg_integer(), binary()}.
-type rbc_wrapped_output() :: hbbft_utils:unicast({{acs, non_neg_integer()}, {{rbc, non_neg_integer()}, hbbft_rbc:val_msg()}}) | hbbft_utils:multicast({{acs, non_neg_integer()}, {{rbc, non_neg_integer()}, hbbft_rbc:echo_msg() | hbbft_rbc:ready_msg()}}).
-type bba_wrapped_output() :: hbbft_utils:multicast({{acs, non_neg_integer()}, hbbft_acs:bba_msg()}).

-spec init(tpke_privkey:privkey(), pos_integer(), non_neg_integer(), non_neg_integer()) -> hbbft_data().
init(SK, N, F, J) ->
    #hbbft_data{secret_key=SK, n=N, f=F, j=J, acs=hbbft_acs:init(SK, N, F, J)}.

%% someone submitting a transaction to the replica set
-spec input(hbbft_data(), binary()) -> {hbbft_data(), ok | {send, [rbc_wrapped_output()]}}.
input(Data = #hbbft_data{buf=Buf}, Txn) ->
    %% add this txn to the the buffer
    NewBuf = queue:in(Txn, Buf),
    io:format("~p got message, queue is ~p~n", [Data#hbbft_data.j, queue:len(NewBuf)]),
    maybe_start_acs(Data#hbbft_data{buf=NewBuf}).

%% The user has constructed something that looks like a block and is telling us which transactions
%% to remove from the buffer (accepted or invalid). Transactions missing causal context
%% (eg. a missing monotonic nonce prior to the current nonce) should remain in the buffer and thus
%% should not be placed in TransactionsToRemove. Once this returns, the user should call next_round/1.
-spec finalize_round(hbbft_data(), [binary()], binary()) -> {hbbft_data(), {send, [hbbft_utils:multicast(sign_msg())]}}.
finalize_round(Data, TransactionsToRemove, ThingToSign) ->
    NewBuf = queue:filter(fun(Item) ->
                                  not lists:member(Item, TransactionsToRemove)
                          end, Data#hbbft_data.buf),
    io:format("~b finalizing round, removed ~p elements from buf~n", [Data#hbbft_data.j, queue:len(Data#hbbft_data.buf) - queue:len(NewBuf)]),
    HashThing = tpke_pubkey:hash_message(tpke_privkey:public_key(Data#hbbft_data.secret_key), ThingToSign),
    BinShare = hbbft_utils:share_to_binary(tpke_privkey:sign(Data#hbbft_data.secret_key, HashThing)),
    %% multicast the signature to everyone
    {Data#hbbft_data{thingtosign=HashThing, buf=NewBuf}, {send, [{multicast, {sign, Data#hbbft_data.round, BinShare}}]}}.

%% The user has obtained a signature and is ready to go to the next round
-spec next_round(hbbft_data()) -> {hbbft_data(), ok | {send, []}}.
next_round(Data = #hbbft_data{secret_key=SK, n=N, f=F, j=J}) ->
    %% reset all the round-dependant bits of the state and increment the round
    NewData = Data#hbbft_data{round=Data#hbbft_data.round + 1, acs=hbbft_acs:init(SK, N, F, J),
                              acs_init=false, acs_results=[],
                              sent_txns=false, sent_sig=false,
                              dec_shares=#{}, decrypted=#{},
                              sig_shares=#{}, thingtosign=undefined},
    maybe_start_acs(NewData).

-spec handle_msg(hbbft_data(), non_neg_integer(), acs_msg() | dec_msg() | sign_msg()) -> {hbbft_data(), ok |
                                                                                          {send, [hbbft_utils:multicast(dec_msg() | sign_msg()) | rbc_wrapped_output() | bba_wrapped_output()]} |
                                                                                          {result, {transactions, [binary()]}} |
                                                                                          {result, {signature, binary()}}}.
handle_msg(Data = #hbbft_data{round=R}, J, {{acs, R}, ACSMsg}) ->
    %% ACS message for this round
    case hbbft_acs:handle_msg(Data#hbbft_data.acs, J, ACSMsg) of
        {NewACS, ok} ->
            {Data#hbbft_data{acs=NewACS}, ok};
        {NewACS, {send, ACSResponse}} ->
            {Data#hbbft_data{acs=NewACS}, {send, hbbft_utils:wrap({acs, Data#hbbft_data.round}, ACSResponse)}};
        {NewACS, {result, Results}} ->
            %% ACS[r] has returned, time to move on to the decrypt phase
            io:format("~b ACS[~b] result ~p~n", [Data#hbbft_data.j, Data#hbbft_data.round, hd(Results)]),
            %% start decrypt phase
            Replies = lists:map(fun({I, Result}) ->
                                        EncKey = get_encrypted_key(Data#hbbft_data.secret_key, Result),
                                        Share = tpke_privkey:decrypt_share(Data#hbbft_data.secret_key, EncKey),
                                        SerializedShare = hbbft_utils:share_to_binary(Share),
                                        {multicast, {dec, Data#hbbft_data.round, I, SerializedShare}}
                                end, Results),
            {Data#hbbft_data{acs=NewACS, acs_results=Results}, {send, Replies}}
    end;
handle_msg(Data = #hbbft_data{round=R}, J, {dec, R, I, Share}) ->
    %% the Share now is a binary, deserialize it and then store in the dec_shares map
    DeserializedShare = hbbft_utils:binary_to_share(Share, Data#hbbft_data.secret_key),
    NewShares = maps:put({I, J}, DeserializedShare, Data#hbbft_data.dec_shares),
    %% check if we have enough to decode the bundle
    SharesForThisBundle = [ S || {{Idx, _}, S} <- maps:to_list(NewShares), I == Idx],
    case length(SharesForThisBundle) > Data#hbbft_data.f andalso not maps:is_key({I, J}, Data#hbbft_data.dec_shares) andalso lists:keymember(I, 1, Data#hbbft_data.acs_results) of
        true ->
            io:format("~p got enough shares to decrypt bundle ~n", [Data#hbbft_data.j]),
            {I, Enc} = lists:keyfind(I, 1, Data#hbbft_data.acs_results),
            EncKey = get_encrypted_key(Data#hbbft_data.secret_key, Enc),
            %% TODO verify the shares with verify_share/3
            DecKey = tpke_pubkey:combine_shares(tpke_privkey:public_key(Data#hbbft_data.secret_key), EncKey, SharesForThisBundle),
            case decrypt(DecKey, Enc) of
                error ->
                    io:format("failed to decrypt bundle!~n"),
                    {Data#hbbft_data{dec_shares=NewShares}, ok};
                Decrypted ->
                    NewDecrypted = maps:put(I, binary_to_term(Decrypted), Data#hbbft_data.decrypted),
                    case maps:size(NewDecrypted) == length(Data#hbbft_data.acs_results) andalso not Data#hbbft_data.sent_txns of
                        true ->
                            %% we did it!
                            io:format("~p finished decryption phase!~n", [Data#hbbft_data.j]),
                            %% Combine all unique messages into a single list
                            TransactionsThisRound = lists:usort(lists:flatten(maps:values(NewDecrypted))),
                            %% return the transactions we agreed on to the user
                            %% we have no idea which transactions are valid, invalid, out of order or missing
                            %% causal context (eg. a nonce is not monotonic) so we return them to the user to let them
                            %% figure it out. We expect the user to call finalize_round/3 once they've decided what they want to accept
                            %% from this set of transactions.
                            {Data#hbbft_data{dec_shares=NewShares, decrypted=NewDecrypted, sent_txns=true}, {result, {transactions, TransactionsThisRound}}};
                        false ->
                            {Data#hbbft_data{dec_shares=NewShares, decrypted=NewDecrypted}, ok}
                    end
            end;
        false ->
            %% not enough shares yet
            {Data#hbbft_data{dec_shares=NewShares}, ok}
    end;
handle_msg(Data = #hbbft_data{round=R, thingtosign=ThingToSign}, J, {sign, R, BinShare}) when ThingToSign /= undefined ->
    %% messages related to signing the final block for this round, see finalize_round for more information
    %% this is an extension to the HoneyBadger BFT specification
    Share = hbbft_utils:binary_to_share(BinShare, Data#hbbft_data.secret_key),
    %% verify the share
    case tpke_pubkey:verify_signature_share(tpke_privkey:public_key(Data#hbbft_data.secret_key), Share, ThingToSign) of
        true ->
            io:format("~b got valid signature share~n", [Data#hbbft_data.j]),
            NewSigShares = maps:put(J, Share, Data#hbbft_data.sig_shares),
            %% check if we have at least f+1 shares
            case maps:size(NewSigShares) > Data#hbbft_data.f andalso not Data#hbbft_data.sent_sig of
                true ->
                    %% ok, we have enough people agreeing with us we can return the signature
                    Sig = tpke_pubkey:combine_signature_shares(tpke_privkey:public_key(Data#hbbft_data.secret_key), maps:values(NewSigShares)),
                    {Data#hbbft_data{sig_shares=NewSigShares, sent_sig=true}, {result, {signature, erlang_pbc:element_to_binary(Sig)}}};
                false ->
                    {Data#hbbft_data{sig_shares=NewSigShares}, ok}
            end;
        false ->
            io:format("~p got bad signature share from ~p~n", [Data#hbbft_data.j, J]),
            {Data, ok}
    end;
handle_msg(Data, J, Msg) ->
    io:format("~p ignoring message ~p from ~p in round ~p ~n", [Data#hbbft_data.j, Msg, J, Data#hbbft_data.round]),
    {Data, ok}.

-spec maybe_start_acs(hbbft_data()) -> {hbbft_data(), ok | {send, [rbc_wrapped_output()]}}.
maybe_start_acs(Data = #hbbft_data{n=N, secret_key=SK}) ->
    case queue:len(Data#hbbft_data.buf) > ?BATCH_SIZE andalso Data#hbbft_data.acs_init == false of
        true ->
            %% compose a transaction bundle
            %% get the top b elements from buf
            %% pick a random B/N selection of them
            Proposed = hbbft_utils:random_n(?BATCH_SIZE div N, lists:sublist(queue:to_list(Data#hbbft_data.buf), ?BATCH_SIZE)),
            %% encrypt x -> tpke.enc(pk, proposed)
            EncX = encrypt(tpke_privkey:public_key(SK), term_to_binary(Proposed)),
            %% time to kick off a round
            {NewACSState, {send, ACSResponse}} = hbbft_acs:input(Data#hbbft_data.acs, EncX),
            io:format("~p has initiated ACS~n", [Data#hbbft_data.j]),
            %% add this to acs set in data and send out the ACS response(s)
            {Data#hbbft_data{acs=NewACSState, acs_init=true},
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
    {U, V, W} = tpke_pubkey:encrypt(PK, Key),
    UBin = erlang_pbc:element_to_binary(U),
    WBin = erlang_pbc:element_to_binary(W),
    EncKey = <<(byte_size(UBin)):8/integer-unsigned, UBin/binary, V:32/binary, (byte_size(WBin)):8/integer-unsigned, WBin/binary>>,
    io:format("Enc key is ~p bytes (~p ~p ~p)~n", [byte_size(EncKey), byte_size(UBin), byte_size(V), byte_size(WBin)]),
    %% encrypt the bundle with AES-GCM and put the IV and the encrypted key in the Additional Authenticated Data (AAD)
    AAD = <<IV:16/binary, (byte_size(EncKey)):16/integer-unsigned, EncKey/binary>>,
    {CipherText, CipherTag} = crypto:block_encrypt(aes_gcm, Key, IV, {AAD, Bin}),
    %% assemble a final binary packet
    <<AAD/binary, CipherTag:16/binary, CipherText/binary>>.

-spec get_encrypted_key(tpke_privkey:privkey(), binary()) -> tpke_pubkey:ciphertext().
get_encrypted_key(SK, <<_IV:16/binary, EncKeySize:16/integer-unsigned, EncKey:EncKeySize/binary, _/binary>>) ->
    <<USize:8/integer-unsigned, UBin:USize/binary, V:32/binary, WSize:8/integer-unsigned, WBin:WSize/binary>> = EncKey,
    PubKey = tpke_privkey:public_key(SK),
    U = tpke_pubkey:deserialize_element(PubKey, UBin),
    W = tpke_pubkey:deserialize_element(PubKey, WBin),
    {U, V, W}.

-spec decrypt(binary(), binary()) -> binary() | error.
decrypt(Key, Bin) ->
    <<IV:16/binary, EncKeySize:16/integer-unsigned, EncKey:EncKeySize/binary, Tag:16/binary, CipherText/binary>> = Bin,
    crypto:block_decrypt(aes_gcm, Key, IV, {<<IV:16/binary, EncKeySize:16/integer-unsigned, EncKey:(EncKeySize)/binary>>, CipherText, Tag}).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

merge_replies(N, NewReplies, Replies) when N < 0 orelse length(NewReplies) == 0 ->
    Replies;
merge_replies(N, NewReplies, Replies) ->
    case lists:keyfind(N, 1, NewReplies) of
        false ->
            merge_replies(N-1, lists:keydelete(N, 1, NewReplies), Replies);
        {N, ok} ->
            merge_replies(N-1, lists:keydelete(N, 1, NewReplies), Replies);
        {N, {send, ToSend}} ->
            NewSend = case lists:keyfind(N, 1, Replies) of
                          false ->
                              {N, {send, ToSend}};
                          {N, OldSend} ->
                              {N, {send, OldSend ++ ToSend}}
                      end,
            merge_replies(N-1, lists:keydelete(N, 1, NewReplies), lists:keystore(N, 1, Replies, NewSend))
    end.

hbbft_init_test_() ->
    {timeout, 60, [
                   fun() ->
                           N = 5,
                           F = 1,
                           dealer:start_link(N, F+1, 'SS512'),
                           {ok, PubKey, PrivateKeys} = dealer:deal(),
                           gen_server:stop(dealer),
                           StatesWithIndex = [{J, hbbft:init(Sk, N, F, J)} || {J, Sk} <- lists:zip(lists:seq(0, N - 1), PrivateKeys)],
                           Msgs = [ crypto:strong_rand_bytes(128) || _ <- lists:seq(1, N*20)],
                           %% send each message to a random subset of the HBBFT actors
                           {NewStates, Replies} = lists:foldl(fun(Msg, {States, Replies}) ->
                                                                      Destinations = hbbft_utils:random_n(rand:uniform(N), States),
                                                                      {NewStates, NewReplies} = lists:unzip(lists:map(fun({J, Data}) ->
                                                                                                                              {NewData, Reply} = hbbft:input(Data, Msg),
                                                                                                                              {{J, NewData}, {J, Reply}}
                                                                                                                      end, lists:keysort(1, Destinations))),
                                                                      {lists:ukeymerge(1, NewStates, States), merge_replies(N, NewReplies, Replies)}
                                                              end, {StatesWithIndex, []}, Msgs),
                           %% check that at least N-F actors have started ACS:
                           ?assert(length(Replies) >= N - F),
                           %% all the nodes that have started ACS should have tried to send messages to all N peers (including themselves)
                           ?assert(lists:all(fun(E) -> E end, [ length(R) == N+1 || {_, {send, R}} <- Replies ])),
                           %% start it on runnin'
                           {NextStates, ConvergedResults} = hbbft_test_utils:do_send_outer(?MODULE, Replies, NewStates, sets:new()),
                           %io:format("Converged Results ~p~n", [ConvergedResults]),
                           %% check all N actors returned a result
                           ?assertEqual(N, sets:size(ConvergedResults)),
                           DistinctResults = sets:from_list([BVal || {result, {_, BVal}} <- sets:to_list(ConvergedResults)]),
                           %% check all N actors returned the same result
                           ?assertEqual(1, sets:size(DistinctResults)),
                           %io:format("DistinctResults ~p~n", [sets:to_list(DistinctResults)]),
                           {_, [AcceptedMsgs]} = lists:unzip(lists:flatten(sets:to_list(DistinctResults))),
                           %% check all the Msgs are actually from the original set
                           ?assert(sets:is_subset(sets:from_list(AcceptedMsgs), sets:from_list(Msgs))),
                           %% ok, tell HBBFT we like all its transactions and give it a block to sign
                           Block = term_to_binary({block, AcceptedMsgs}),
                           {EvenNewerStates, NewReplies} = lists:foldl(fun({J, S}, {States, Replies2}) ->
                                                                               {NewS, Res}= hbbft:finalize_round(S, AcceptedMsgs, Block),
                                                                               {lists:keyreplace(J, 1, States, {J, NewS}), merge_replies(N, [{J, Res}], Replies2)}
                                                                       end, {NextStates, []}, NextStates),
                           %% ok, run the rest of the round to completion
                           {NextStates2, ConvergedResults2} = hbbft_test_utils:do_send_outer(?MODULE, NewReplies, EvenNewerStates, sets:new()),
                           %?assertEqual(N, sets:size(ConvergedResults2)),
                           DistinctResults2 = sets:from_list([BVal || {result, {_, BVal}} <- sets:to_list(ConvergedResults2)]),
                           [{signature, Sig}] = sets:to_list(DistinctResults2),
                           Signature = tpke_pubkey:deserialize_element(PubKey, Sig),
                           %% everyone should have converged to the same signature
                           ?assertEqual(1, sets:size(DistinctResults)),
                           HM = tpke_pubkey:hash_message(PubKey, Block),
                           ?assert(tpke_pubkey:verify_signature(PubKey, Signature, HM)),
                           %% ok, now we need to go onto the next round
                           {PenultimateStates, PenultimateReplies} = lists:foldl(fun({J, S}, {States, Replies2}) ->
                                                                                         {NewS, Res}= hbbft:next_round(S),
                                                                                         {lists:keyreplace(J, 1, States, {J, NewS}), merge_replies(N, [{J, Res}], Replies2)}
                                                                                 end, {NextStates2, []}, NextStates2),
                           {_NextStates3, _ConvergedResults3} = hbbft_test_utils:do_send_outer(?MODULE, PenultimateReplies, PenultimateStates, sets:new()),
                           _DistinctResults3 = sets:from_list([BVal || {result, {_, BVal}} <- sets:to_list(ConvergedResults2)]),
                           {_, [AcceptedMsgs2]} = lists:unzip(lists:flatten(sets:to_list(DistinctResults))),
                           %% check all the Msgs are actually from the original set
                           ?assert(sets:is_subset(sets:from_list(AcceptedMsgs2), sets:from_list(Msgs))),
                           ok
                   end
                  ]}.

hbbft_one_actor_no_txns_test_() ->
    {timeout, 60, [
                   fun() ->
                           N = 5,
                           F = 1,
                           dealer:start_link(N, F+1, 'SS512'),
                           {ok, _PubKey, PrivateKeys} = dealer:deal(),
                           gen_server:stop(dealer),
                           StatesWithIndex = [{J, hbbft:init(Sk, N, F, J)} || {J, Sk} <- lists:zip(lists:seq(0, N - 1), PrivateKeys)],
                           Msgs = [ crypto:strong_rand_bytes(128) || _ <- lists:seq(1, N*10)],
                           %% send each message to a random subset of the HBBFT actors
                           {NewStates, Replies} = lists:foldl(fun(Msg, {States, Replies}) ->
                                                                      Destinations = hbbft_utils:random_n(rand:uniform(N-1), lists:sublist(States, N-1)),
                                                                      {NewStates, NewReplies} = lists:unzip(lists:map(fun({J, Data}) ->
                                                                                                                              {NewData, Reply} = hbbft:input(Data, Msg),
                                                                                                                              {{J, NewData}, {J, Reply}}
                                                                                                                      end, lists:keysort(1, Destinations))),
                                                                      {lists:ukeymerge(1, NewStates, States), merge_replies(N, NewReplies, Replies)}
                                                              end, {StatesWithIndex, []}, Msgs),
                           %% check that at least N-F actors have started ACS:
                           io:format("~p replies~n", [length(Replies)]),
                           ?assert(length(Replies) >= N - F),
                           %% all the nodes that have started ACS should have tried to send messages to all N peers (including themselves)
                           ?assert(lists:all(fun(E) -> E end, [ length(R) == N+1 || {_, {send, R}} <- Replies ])),
                           %% start it on runnin'
                           {_, ConvergedResults} = hbbft_test_utils:do_send_outer(?MODULE, Replies, NewStates, sets:new()),
                           %io:format("Converged Results ~p~n", [ConvergedResults]),
                           %% check all N actors returned a result
                           ?assertEqual(N, sets:size(ConvergedResults)),
                           DistinctResults = sets:from_list([BVal || {result, {_, BVal}} <- sets:to_list(ConvergedResults)]),
                           %% check all N actors returned the same result
                           ?assertEqual(1, sets:size(DistinctResults)),
                           {_, AcceptedMsgs} = lists:unzip(lists:flatten(sets:to_list(DistinctResults))),
                           %io:format("~p~n", [AcceptedMsgs]),
                           %% check all the Msgs are actually from the original set
                           ?assert(sets:is_subset(sets:from_list(lists:flatten(AcceptedMsgs)), sets:from_list(Msgs))),
                           ok
                   end
                  ]}.

hbbft_two_actors_no_txns_test_() ->
    {timeout, 60, [
                   fun() ->
                           N = 5,
                           F = 1,
                           dealer:start_link(N, F+1, 'SS512'),
                           {ok, _PubKey, PrivateKeys} = dealer:deal(),
                           gen_server:stop(dealer),
                           StatesWithIndex = [{J, hbbft:init(Sk, N, F, J)} || {J, Sk} <- lists:zip(lists:seq(0, N - 1), PrivateKeys)],
                           Msgs = [ crypto:strong_rand_bytes(128) || _ <- lists:seq(1, N*10)],
                           %% send each message to a random subset of the HBBFT actors
                           {NewStates, Replies} = lists:foldl(fun(Msg, {States, Replies}) ->
                                                                      Destinations = hbbft_utils:random_n(rand:uniform(N-2), lists:sublist(States, N-2)),
                                                                      {NewStates, NewReplies} = lists:unzip(lists:map(fun({J, Data}) ->
                                                                                                                              {NewData, Reply} = hbbft:input(Data, Msg),
                                                                                                                              {{J, NewData}, {J, Reply}}
                                                                                                                      end, lists:keysort(1, Destinations))),
                                                                      {lists:ukeymerge(1, NewStates, States), merge_replies(N, NewReplies, Replies)}
                                                              end, {StatesWithIndex, []}, Msgs),
                           %% check that at least N-F actors have started ACS:
                           io:format("~p replies~n", [length(Replies)]),
                           ?assert(length(Replies) =< N - F),
                           %% all the nodes that have started ACS should have tried to send messages to all N peers (including themselves)
                           ?assert(lists:all(fun(E) -> E end, [ length(R) == N+1 || {_, {send, R}} <- Replies ])),
                           %% start it on runnin'
                           {_, ConvergedResults} = hbbft_test_utils:do_send_outer(?MODULE, Replies, NewStates, sets:new()),
                           %% check no actors returned a result
                           ?assertEqual(0, sets:size(ConvergedResults)),
                           ok
                   end
                  ]}.

hbbft_one_actor_missing_test_() ->
    {timeout, 60, [
                   fun() ->
                           N = 5,
                           F = 1,
                           dealer:start_link(N, F+1, 'SS512'),
                           {ok, _PubKey, PrivateKeys} = dealer:deal(),
                           gen_server:stop(dealer),
                           StatesWithIndex = [{J, hbbft:init(Sk, N, F, J)} || {J, Sk} <- lists:zip(lists:seq(0, N - 2), lists:sublist(PrivateKeys, N-1))],
                           Msgs = [ crypto:strong_rand_bytes(128) || _ <- lists:seq(1, N*10)],
                           %% send each message to a random subset of the HBBFT actors
                           {NewStates, Replies} = lists:foldl(fun(Msg, {States, Replies}) ->
                                                                      Destinations = hbbft_utils:random_n(rand:uniform(N-1), States),
                                                                      {NewStates, NewReplies} = lists:unzip(lists:map(fun({J, Data}) ->
                                                                                                                              {NewData, Reply} = hbbft:input(Data, Msg),
                                                                                                                              {{J, NewData}, {J, Reply}}
                                                                                                                      end, lists:keysort(1, Destinations))),
                                                                      {lists:ukeymerge(1, NewStates, States), merge_replies(N, NewReplies, Replies)}
                                                              end, {StatesWithIndex, []}, Msgs),
                           %% check that at least N-F actors have started ACS:
                           io:format("~p replies~n", [length(Replies)]),
                           ?assert(length(Replies) >= N - F),
                           %% all the nodes that have started ACS should have tried to send messages to all N peers (including themselves)
                           ?assert(lists:all(fun(E) -> E end, [ length(R) == N+1 || {_, {send, R}} <- Replies ])),
                           %% start it on runnin'
                           {_, ConvergedResults} = hbbft_test_utils:do_send_outer(?MODULE, Replies, NewStates, sets:new()),
                           %% check no actors returned a result
                           ?assertEqual(4, sets:size(ConvergedResults)),
                           DistinctResults = sets:from_list([BVal || {result, {_, BVal}} <- sets:to_list(ConvergedResults)]),
                           %% check all N actors returned the same result
                           ?assertEqual(1, sets:size(DistinctResults)),
                           {_, AcceptedMsgs} = lists:unzip(lists:flatten(sets:to_list(DistinctResults))),
                           %% check all the Msgs are actually from the original set
                           ?assert(sets:is_subset(sets:from_list(lists:flatten(AcceptedMsgs)), sets:from_list(Msgs))),
                           ok
                   end
                  ]}.

hbbft_two_actor_missing_test_() ->
    {timeout, 60, [
                   fun() ->
                           N = 5,
                           F = 1,
                           dealer:start_link(N, F+1, 'SS512'),
                           {ok, _PubKey, PrivateKeys} = dealer:deal(),
                           gen_server:stop(dealer),
                           StatesWithIndex = [{J, hbbft:init(Sk, N, F, J)} || {J, Sk} <- lists:zip(lists:seq(0, N - 3), lists:sublist(PrivateKeys, N-2))],
                           Msgs = [ crypto:strong_rand_bytes(128) || _ <- lists:seq(1, N*10)],
                           %% send each message to a random subset of the HBBFT actors
                           {NewStates, Replies} = lists:foldl(fun(Msg, {States, Replies}) ->
                                                                      Destinations = hbbft_utils:random_n(rand:uniform(N-2), States),
                                                                      {NewStates, NewReplies} = lists:unzip(lists:map(fun({J, Data}) ->
                                                                                                                              {NewData, Reply} = hbbft:input(Data, Msg),
                                                                                                                              {{J, NewData}, {J, Reply}}
                                                                                                                      end, lists:keysort(1, Destinations))),
                                                                      {lists:ukeymerge(1, NewStates, States), merge_replies(N, NewReplies, Replies)}
                                                              end, {StatesWithIndex, []}, Msgs),
                           %% check that at least N-F actors have started ACS:
                           io:format("~p replies~n", [length(Replies)]),
                           ?assert(length(Replies) =< N - F),
                           %% all the nodes that have started ACS should have tried to send messages to all N peers (including themselves)
                           ?assert(lists:all(fun(E) -> E end, [ length(R) == N+1 || {_, {send, R}} <- Replies ])),
                           %% start it on runnin'
                           {_, ConvergedResults} = hbbft_test_utils:do_send_outer(?MODULE, Replies, NewStates, sets:new()),
                           %% check no actors returned a result
                           ?assertEqual(0, sets:size(ConvergedResults)),
                           ok
                   end
                  ]}.


encrypt_decrypt_test() ->
    N = 5,
    F = 1,
    dealer:start_link(N, F+1, 'SS512'),
    {ok, PubKey, PrivateKeys} = dealer:deal(),
    gen_server:stop(dealer),

    PlainText = crypto:strong_rand_bytes(24),
    Enc = encrypt(PubKey, PlainText),
    EncKey = get_encrypted_key(hd(PrivateKeys), Enc),
    DecKey = tpke_pubkey:combine_shares(PubKey, EncKey, [ tpke_privkey:decrypt_share(SK, EncKey) || SK <- PrivateKeys]),
    ?assertEqual(PlainText, decrypt(DecKey, Enc)),
    ok.

-endif.

