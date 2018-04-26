-record(rbc_state, {
          rbc_data :: hbbft_rbc:rbc_data(),
          result :: undefined | binary()
         }).

-record(bba_state, {
          bba_data :: hbbft_bba:bba_data(),
          input :: undefined | 0 | 1,
          result :: undefined | boolean()
         }).

-record(acs_data, {
          done = false :: boolean(),
          n :: pos_integer(),
          f :: non_neg_integer(),
          j :: non_neg_integer(),
          rbc = #{} :: #{non_neg_integer() => hbbft_acs:rbc_state()},
          bba = #{} :: #{non_neg_integer() => hbbft_acs:bba_state()}
         }).

-record(acs_serialized_data, {
          done = false :: boolean(),
          n :: pos_integer(),
          f :: non_neg_integer(),
          j :: non_neg_integer(),
          rbc = #{} :: #{non_neg_integer() => hbbft_acs:rbc_serialized_state()},
          bba = #{} :: #{non_neg_integer() => hbbft_acs:bba_serialized_state()}
         }).

-record(rbc_serialized_state, {
          rbc_data :: hbbft_rbc:rbc_serialized_data(),
          result :: undefined | binary()
         }).

-record(bba_serialized_state, {
          bba_data :: hbbft_bba:bba_serialized_data(),
          input :: undefined | 0 | 1,
          result :: undefined | boolean()
         }).
