-define(timer(Mark, Expr),
        begin
            __Start = erlang:monotonic_time(millisecond),
            __Ret = (Expr),
            __End = erlang:monotonic_time(millisecond),
            case  __End - __Start of
                __Total when __Total > 3 ->
                    lager:info("~p took ~pms", [Mark, __Total]);
                _ -> ok
            end,
            __Ret
        end).
