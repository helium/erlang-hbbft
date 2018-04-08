-module(hbbft). %% big kahuna

-export([init/5, input/2, get_encrypted_key/2, decrypt/2, handle_msg/3]).

-record(data, {
          pubkey,
          state = waiting :: waiting | done,
          secret_key,
          n :: pos_integer(),
          f :: pos_integer(),
          j :: non_neg_integer(),
          round = 0 :: non_neg_integer(),
          buf = queue:new(),
          acs = sets:new()
         }).

-define(BATCH_SIZE, 16384).

init(PK, SK, N, F, J) ->
    #data{pubkey=PK, secret_key=SK, n=N, f=F, j=J}.

input(Data = #data{pubkey=PK, secret_key=SK, n=N, f=F}, Txn) ->
    case queue:len(Data#data.buf) > ?BATCH_SIZE andalso sets:is_empty(Data#data.acs) of
        true ->
            %% compose a transaction bundle
            %% get the top b elements from buf
            %% pick a random B/N selection of them
            Proposed = random_n(?BATCH_SIZE div N, lists:sublist(queue:to_list(Data#data.buf), ?BATCH_SIZE)),
            %% encrypt x -> tpke.enc(pk, proposed)
            EncX = encrypt(PK, term_to_binary(Proposed)),
            %% time to kick off a round
            ACSState = acs:init(SK, N, F),
            {NewACSState, ACSResult} = acs:input(ACSState, Data#data.round, EncX),
            %% add this to acs set in data
            Data#data{state=waiting, acs=sets:add_element({NewACSState, ACSResult}, Data#data.acs), buf=queue:in(Txn, Data#data.buf)},
            ok;
        false ->
            %% it is possible that buf has not yet been filled but there is another node
            %% which completed ACS
            case recv_acs() of
                [] ->
                    %% not enough transactions for this round yet
                    %% add this txn to the the buffer
                    Data#data{state=waiting, buf=queue:in(Txn, Data#data.buf)},
                    ok;
                %% may return a bunch of ACS which Pi may not have yet seen
                RecvACSList ->
                    %% add the ACS results Pi hasn't seen before to data.acs
                    UnseenACSes = lists:filter(fun(E) -> sets:is_element(E, Data#data.acs) end, RecvACSList),
                    Data#data{state=waiting, acs=sets:union(UnseenACSes, Data#data.acs), buf=queue:in(Txn, Data#data.buf)}
            end
    end.

handle_msg(_, _, _) ->
    ok.

recv_acs() ->
    %% list containing {ACSState, ACSResult} from other nodes?
    ok.

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

hbbft_init_test() ->
    N = 5,
    F = 1,
    dealer:start_link(N, F+1, 'SS512'),
    {ok, PubKey, PrivateKeys} = dealer:deal(),
    gen_server:stop(dealer),

    ?assert(false),
    ok.

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

