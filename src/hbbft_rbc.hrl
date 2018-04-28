-record(rbc_data, {
          state = init :: init | waiting | done,
          %% each rbc actor must know its identity
          pid :: non_neg_integer(),
          %% each rbc actor must know who the leader is
          %% this would be used for determining who broadcasts the VAL message
          leader :: non_neg_integer(),
          n :: pos_integer(),
          f :: non_neg_integer(),
          msg = undefined :: binary() | undefined,
          num_echoes = #{} :: #{merkerl:hash() => [non_neg_integer()]},
          num_readies = #{} :: #{merkerl:hash() => [non_neg_integer()]},
          seen_val = false :: boolean(),
          ready_sent = false :: boolean(),
          %% roothash: #{sender: {size, shard}}
          stripes = #{} :: #{merkerl:hash() => #{non_neg_integer() => {pos_integer(), binary()}}}
         }).

%% Note: This record is perhaps not needed.
%% RBC is independent and does not need to be serialized.
%% It has only been added for uniformity.
-record(rbc_serialized_data, {
          state = init :: init | waiting | done,
          pid :: non_neg_integer(),
          leader :: non_neg_integer(),
          n :: pos_integer(),
          f :: non_neg_integer(),
          msg = undefined :: binary() | undefined,
          h = undefined :: binary() | undefined,
          shares = [] :: [{merkerl:proof(), {pos_integer(), binary()}}],
          num_echoes = #{} :: #{merkerl:hash() => [non_neg_integer()]},
          num_readies = #{} :: #{merkerl:hash() => [non_neg_integer()]},
          seen_val = false :: boolean(),
          ready_sent = false :: boolean(),
          stripes = #{} :: #{merkerl:hash() => #{non_neg_integer() => {pos_integer(), binary()}}}
         }).
