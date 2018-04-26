-record(rbc_data, {
          state = init :: init | waiting | done,
          n :: pos_integer(),
          f :: non_neg_integer(),
          msg = undefined :: binary() | undefined,
          h = undefined :: binary() | undefined,
          shares = [] :: [{merkerl:proof(), {pos_integer(), binary()}}],
          num_echoes = [] :: [non_neg_integer()],
          num_readies = [] :: [non_neg_integer()],
          seen_val = false :: boolean(),
          ready_sent = false :: boolean()
         }).

-record(rbc_serialized_data, {
          state = init :: init | waiting | done,
          n :: pos_integer(),
          f :: non_neg_integer(),
          msg = undefined :: binary() | undefined,
          h = undefined :: binary() | undefined,
          shares = [] :: [{merkerl:proof(), {pos_integer(), binary()}}],
          num_echoes = [] :: [non_neg_integer()],
          num_readies = [] :: [non_neg_integer()],
          seen_val = false :: boolean(),
          ready_sent = false :: boolean()
         }).
