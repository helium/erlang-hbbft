-module(hbbft). %% big kahuna

-export([init/4, input/2, handle_msg/3]).

-record(data, {
          secret_key,
          n :: pos_integer(),
          f :: pos_integer(),
          j :: non_neg_integer(),
          round = 0 :: non_neg_integer(),
          buf = queue:new(),
          acs
         }).

-define(BATCH_SIZE, 16384).

init(SK, N, F, J) ->
    #data{secret_key=SK, n=N, f=F, j=J}.

input(Data = #data{secret_key=SK, n=N, f=F}, Txn) ->
    Buf = queue:in(Txn, Data#data.buf),
    case queue:len(Buf) > ?BATCH_SIZE andalso Data#data.acs == undefined of
        true ->
            %% time to kick off a round
            ACS = acs:init(SK, N, F),
            %% compose a transaction bundle
            %%
            %% get the top b elements from buf
            List = lists:sublist(queue:to_list(Buf), ?BATCH_SIZE),
            %% pick a random B/N selection of them
            Bundle = random_n(?BATCH_SIZE div N, List),
            EncBundle = encrypt(SK, term_to_binary(Bundle)),
            ok
    end.

handle_msg(_, _, _) ->
    ok.




encrypt(PK, Bin) ->
    %% generate a random AES key and IV
    Key = crypto:strong_rand_bytes(32),
    IV = crypto:strong_rand_bytes(16),
    %% encrypt that random AES key with the HBBFT replica set's public key
    %% TODO the result of the encryption is a 3-tuple that contains 2 PBC Elements and a 32 byte binary
    %% we need to encode all this crap into a binary value that we can unpack again sanely
    EncKey = tpke_pubkey:encrypt(PK, Key),
    %% encrypt the bundle with AES-GCM and put the IV and the encrypted key in the Additional Authenticated Data (AAD)
    AAD = <<IV:16/binary, EncKey:32/binary>>,
    {CipherText, CipherTag} = crypto:block_encrypt(aes_gcm, Key, IV, {AAD, Bin}),
    %% assemble a final binary packet
    <<AAD:48/binary, CipherTag:16/binary, CipherText/binary>>.

get_encrypted_key(<<_IV:16/binary, EncKey:32/binary, _/binary>>) ->
    EncKey.

decrypt(SK, Key, Bin) ->
    EncKey = get_encrypted_key(Bin),
    case EncKey == tpke_pubkey:encrypt(tkpe_privkey:public_key(SK), Key) of
        true ->
            %% ok, key matches
            <<IV:16/binary, EncKey:32/binary, Tag:16/binary, CipherText/binary>> = Bin,
            crypto:block_decrypt(aes_gcm, Key, IV, {<<IV:16/binary, EncKey:32/binary>>, CipherText, Tag});
        false ->
            error
    end.

%% helpers
random_n(N, List) ->
    lists:sublist(shuffle(List), N).

shuffle(List) ->
    [X || {_,X} <- lists:sort([{rand:uniform(), N} || N <- List])].

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

encrypt_decrypt_test() ->
    N = 5,
    F = 1,
    dealer:start_link(N, F+1, 'SS512'),
    {ok, PubKey, PrivateKeys} = dealer:deal(),
    gen_server:stop(dealer),

    PlainText = crypto:strong_rand_bytes(24),
    Enc = encrypt(Pubkey, PlainText),
    EncKey = get_encrypted_key(Enc),
    DecKey = tkpe_pubkey:combine_shares([ tpke_privkey:decrypt_share(SK, EncKey) || SK <- PrivateKeys]),
    ok.

-endif.

