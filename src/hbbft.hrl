-record(hbbft_data, {
          batch_size :: pos_integer(),
          secret_key :: tpke_privkey:privkey(),
          n :: pos_integer(),
          f :: pos_integer(),
          j :: non_neg_integer(),
          round = 0 :: non_neg_integer(),
          buf = [] :: [binary()],
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

-record(hbbft_serialized_data, {
          batch_size :: pos_integer(),
          n :: pos_integer(),
          f :: pos_integer(),
          j :: non_neg_integer(),
          round = 0 :: non_neg_integer(),
          buf = [] :: [binary()],
          acs :: hbbft_acs:acs_serialized_data(),
          acs_init = false :: boolean(),
          sent_txns = false :: boolean(),
          sent_sig = false :: boolean(),
          acs_results = [] :: [{non_neg_integer(), binary()}],
          decrypted = #{} :: #{non_neg_integer() => [binary()]},
          sig_shares = #{} :: #{non_neg_integer() => {non_neg_integer(), binary()}},
          dec_shares = #{} :: #{non_neg_integer() => {non_neg_integer(), binary()}},
          thingtosign :: undefined | binary()
         }).

