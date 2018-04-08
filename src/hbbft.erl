-module(hbbft). %% big kahuna

-export([init/4, input/2, get_encrypted_key/2, decrypt/2, handle_msg/3]).

-record(data, {
          state = waiting :: waiting | done,
          secret_key,
          n :: pos_integer(),
          f :: pos_integer(),
          j :: non_neg_integer(),
          round = 0 :: non_neg_integer(),
          buf = queue:new(),
          acs,
          acs_init = false,
          acs_results :: undefined | [binary()],
          dec_shares = #{},
          decrypted = #{}
         }).

-define(BATCH_SIZE, 5).

init(SK, N, F, J) ->
    #data{secret_key=SK, n=N, f=F, j=J, acs=acs:init(SK, N, F)}.

%% someone submitting a transaction to the replica set
input(Data = #data{secret_key=SK, n=N}, Txn) ->
    io:format("~p got message, queue is ~p~n", [Data#data.j, queue:len(Data#data.buf) + 1]),
    case queue:len(Data#data.buf) > ?BATCH_SIZE andalso Data#data.acs_init == false of
        true ->
            %% compose a transaction bundle
            %% get the top b elements from buf
            %% pick a random B/N selection of them
            Proposed = random_n(?BATCH_SIZE div N, lists:sublist(queue:to_list(Data#data.buf), ?BATCH_SIZE)),
            %% encrypt x -> tpke.enc(pk, proposed)
            EncX = encrypt(tpke_privkey:public_key(SK), term_to_binary(Proposed)),
            %% time to kick off a round
            {NewACSState, {send, ACSResponse}} = acs:input(Data#data.acs, Data#data.j, EncX),
            io:format("~p has initiated ACS~n", [Data#data.j]),
            %% add this to acs set in data and send out the ACS response(s)
            {Data#data{state=waiting, acs=NewACSState, acs_init=true, buf=queue:in(Txn, Data#data.buf)},
             {send, wrap({acs, Data#data.round}, ACSResponse)}};
        false ->
            %% not enough transactions for this round yet
            %% add this txn to the the buffer
            {Data#data{state=waiting, buf=queue:in(Txn, Data#data.buf)}, ok}
    end.

handle_msg(Data = #data{round=R}, J, {{acs, R}, ACSMsg}) ->
    %% ACS message for this round
    case acs:handle_msg(Data#data.acs, J, ACSMsg) of
        {NewACS, ok} ->
            {Data#data{acs=NewACS}, ok};
        {NewACS, {send, ACSResponse}} ->
            {Data#data{acs=NewACS}, {send, wrap({acs, Data#data.round}, ACSResponse)}};
        {NewACS, {result, Results}} ->
            %% ACS[r] has returned, time to move on to the decrypt phase
            io:format("~b ACS[~b] result ~p~n", [Data#data.j, Data#data.round, hd(Results)]),
            %% start decrypt phase
            Replies = lists:map(fun({I, Result}) ->
                              EncKey = get_encrypted_key(Data#data.secret_key, Result),
                              Share = tpke_privkey:decrypt_share(Data#data.secret_key, EncKey),
                              {multicast, {dec, Data#data.round, I, Share}}
                      end, Results),
            {Data#data{acs=NewACS, acs_results=Results}, {send, Replies}}
    end;
handle_msg(Data = #data{round=R}, J, {dec, R, I, Share}) ->
    NewShares = maps:put({I, J}, Share, Data#data.dec_shares),
    %% check if we have enough to decode the bundle
    SharesForThisBundle = [ S || {{Idx, _}, S} <- maps:to_list(NewShares), I == Idx],
    case length(SharesForThisBundle) > Data#data.f of
        true ->
            io:format("~p got enough shares to decrypt bundle ~n", [Data#data.j]),
            {I, Enc} = lists:keyfind(I, 1, Data#data.acs_results),
            EncKey = get_encrypted_key(Data#data.secret_key, Enc),
            %% TODO verify the shares with verify_share/3
            DecKey = tpke_pubkey:combine_shares(tpke_privkey:public_key(Data#data.secret_key), EncKey, SharesForThisBundle),
            case decrypt(DecKey, Enc) of
                error ->
                    io:format("failed to decrypt bundle!~n"),
                    {Data#data{dec_shares=NewShares}, ok};
                Decrypted ->
                    NewDecrypted = maps:put(I, binary_to_term(Decrypted), Data#data.decrypted),
                    case maps:size(NewDecrypted) == length(Data#data.acs_results) of
                        true ->
                            %% we did it!
                            io:format("~p finished decryption phase!~n", [Data#data.j]),
                            {Data#data{dec_shares=NewShares, decrypted=NewDecrypted}, {result, maps:to_list(NewDecrypted)}};
                        false ->
                            {Data#data{dec_shares=NewShares, decrypted=NewDecrypted}, ok}
                    end
            end;
        false ->
            %% not enough shares yet
            {Data#data{dec_shares=NewShares}, ok}
    end;
handle_msg(_, _, Msg) ->
    io:format("ignoring message ~p~n", [Msg]),
    ok.

%% wrap a subprotocol's outbound messages with a protocol identifier
wrap(_, []) ->
    [];
wrap(Id, [{multicast, Msg}|T]) ->
    [{multicast, {Id, Msg}}|wrap(Id, T)];
wrap(Id, [{unicast, Dest, Msg}|T]) ->
    [{unicast, Dest, {Id, Msg}}|wrap(Id, T)].

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

get_encrypted_key(SK, <<_IV:16/binary, EncKeySize:16/integer-unsigned, EncKey:EncKeySize/binary, _/binary>>) ->
    <<USize:8/integer-unsigned, UBin:USize/binary, V:32/binary, WSize:8/integer-unsigned, WBin:WSize/binary>> = EncKey,
    %% XXX we don't have a great way to deserialize the elements yet, this is a hack
    Ugh = tpke_pubkey:hash_message(tpke_privkey:public_key(SK), <<"ugh">>),
    U = erlang_pbc:binary_to_element(Ugh, UBin),
    W = erlang_pbc:binary_to_element(Ugh, WBin),
    {U, V, W}.

decrypt(Key, Bin) ->
    <<IV:16/binary, EncKeySize:16/integer-unsigned, EncKey:EncKeySize/binary, Tag:16/binary, CipherText/binary>> = Bin,
    crypto:block_decrypt(aes_gcm, Key, IV, {<<IV:16/binary, EncKeySize:16/integer-unsigned, EncKey:(EncKeySize)/binary>>, CipherText, Tag}).

%% helpers
random_n(N, List) ->
    lists:sublist(shuffle(List), N).

shuffle(List) ->
    [X || {_,X} <- lists:sort([{rand:uniform(), N} || N <- List])].

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
                           {ok, _PubKey, PrivateKeys} = dealer:deal(),
                           gen_server:stop(dealer),
                           StatesWithIndex = [{J, hbbft:init(Sk, N, F, J)} || {J, Sk} <- lists:zip(lists:seq(0, N - 1), PrivateKeys)],
                           Msgs = [ crypto:strong_rand_bytes(512) || _ <- lists:seq(1, N*4)],
                           %% send each message to a random subset of the HBBFT actors
                           {NewStates, Replies} = lists:foldl(fun(Msg, {States, Replies}) ->
                                                                      Destinations = random_n(rand:uniform(N), States),
                                                                      {NewStates, NewReplies} = lists:unzip(lists:map(fun({J, Data}) ->
                                                                                                                              {NewData, Reply} = hbbft:input(Data, Msg),
                                                                                                                              {{J, NewData}, {J, Reply}}
                                                                                                                      end, lists:keysort(1, Destinations))),
                                                                      {lists:ukeymerge(1, NewStates, States), merge_replies(N, NewReplies, Replies)}
                                                              end, {StatesWithIndex, []}, Msgs),
                           %% check that at least N-F actors have started ACS:
                           ?assert(length(Replies) >= N - F),
                           %% all the nodes that have started ACS should have tried to send messages to all N peers (including themselves)
                           ?assert(lists:all(fun(E) -> E end, [ length(R) == 5 || {_, {send, R}} <- Replies ])),
                           %% start it on runnin'
                           ConvergedResults = do_send_outer(Replies, NewStates, sets:new()),
                           %io:format("Converged Results ~p~n", [ConvergedResults]),
                           %% check all N actors returned a result
                           ?assertEqual(N, sets:size(ConvergedResults)),
                           DistinctResults = sets:from_list([BVal || {result, {_, BVal}} <- sets:to_list(ConvergedResults)]),
                           %% check all N actors returned the same result
                           ?assertEqual(1, sets:size(DistinctResults)),
                           %?assert(false),
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

do_send_outer([], _, Acc) ->
    Acc;
do_send_outer([{result, {Id, Result}} | T], Pids, Acc) ->
    do_send_outer(T, Pids, sets:add_element({result, {Id, Result}}, Acc));
do_send_outer([H|T], States, Acc) ->
    {R, NewStates} = do_send(H, [], States),
    do_send_outer(T++R, NewStates, Acc).

do_send({Id, {result, Result}}, Acc, States) ->
    {[{result, {Id, Result}} | Acc], States};
do_send({_, ok}, Acc, States) ->
    {Acc, States};
do_send({_, {send, []}}, Acc, States) ->
    {Acc, States};
do_send({Id, {send, [{unicast, J, Msg}|T]}}, Acc, States) ->
    {J, State} = lists:keyfind(J, 1, States),
    {NewState, Result} = handle_msg(State, Id, Msg),
    do_send({Id, {send, T}}, [{J, Result}|Acc], lists:keyreplace(J, 1, States, {J, NewState}));
do_send({Id, {send, [{multicast, Msg}|T]}}, Acc, States) ->
    Res = lists:map(fun({J, State}) ->
                            {NewState, Result} = handle_msg(State, Id, Msg),
                            {{J, NewState}, {J, Result}}
                    end, States),
    {NewStates, Results} = lists:unzip(Res),
    do_send({Id, {send, T}}, Results ++ Acc, lists:ukeymerge(1, NewStates, States)).

-endif.

