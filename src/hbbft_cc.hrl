-record(cc_data, {
          state = waiting :: waiting | done,
          sk :: tpke_privkey:privkey(),
          %% Note: sid is assumed to be a unique nonce that serves as name of this common coin
          sid :: erlang_pbc:element(),
          n :: pos_integer(),
          f :: non_neg_integer(),
          shares = maps:new() :: #{non_neg_integer() => tpke_privkey:share()}
         }).

-record(cc_serialized_data, {
          state = waiting :: waiting | done,
          sid :: binary(),
          n :: pos_integer(),
          f :: non_neg_integer(),
          shares :: #{non_neg_integer() => binary()}
         }).

