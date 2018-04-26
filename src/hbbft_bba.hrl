-record(bba_data, {
          state = init :: init | waiting | done,
          round = 0 :: non_neg_integer(),
          secret_key :: tpke_privkey:privkey(),
          coin :: undefined | hbbft_cc:cc_data(),
          est :: undefined | 0 | 1,
          output :: undefined | 0 | 1,
          f :: non_neg_integer(),
          n :: pos_integer(),
          witness = maps:new() :: #{non_neg_integer() => 0 | 1},
          aux_witness = maps:new() :: #{non_neg_integer() => 0 | 1},
          aux_sent = false :: boolean(),
          broadcasted = 2#0 :: 0 | 1,
          bin_values = 2#00 :: 0 | 1 | 2 | 3
         }).

-record(bba_serialized_data, {
          state = init :: init | waiting | done,
          round = 0 :: non_neg_integer(),
          coin :: undefined | hbbft_cc:cc_serialized_data(),
          est :: undefined | 0 | 1,
          output :: undefined | 0 | 1,
          f :: non_neg_integer(),
          n :: pos_integer(),
          witness = maps:new() :: #{non_neg_integer() => 0 | 1},
          aux_witness = maps:new() :: #{non_neg_integer() => 0 | 1},
          aux_sent = false :: boolean(),
          broadcasted = 2#0 :: 0 | 1,
          bin_values = 2#00 :: 0 | 1 | 2 | 3
         }).
