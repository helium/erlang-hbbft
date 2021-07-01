-module(hbbft_test_utils).

-export([serialize_key/2, deserialize_key/1, do_send_outer/4, shuffle/1, random_n/2, enumerate/1, merge_replies/3]).

serialize_key('BLS12-381'=Curve, SK) ->
    {Curve, tc_key_share:serialize(SK)}.

deserialize_key({'BLS12-381', SerKey}) ->
    tc_key_share:deserialize(SerKey).

% TODO Type of Acc elements
% TODO Type of States elements
% TODO Type of Results elements
-spec do_send_outer(Module :: atom(), Results :: list(), States, Acc) ->
    {States, Acc}
      when Acc :: sets:set(tuple()),
           States :: list().
do_send_outer(_Mod, [], States, Acc) ->
    {States, Acc};
do_send_outer(Mod, [{result, {Id, Result}} | T], Pids, Acc) ->
    do_send_outer(Mod, T, Pids, sets:add_element({result, {Id, Result}}, Acc));
do_send_outer(Mod, [H|T], States, Acc) ->
    {R, NewStates} = do_send(Mod, H, [], States),
    do_send_outer(Mod, T++R, NewStates, Acc).

do_send(Mod, {Id, {result_and_send, Result, ToSend}}, Acc, States) ->
    do_send(Mod, {Id, ToSend}, [{result, {Id, Result}} | Acc], States);
do_send(_Mod, {Id, {result, Result}}, Acc, States) ->
    {[{result, {Id, Result}} | Acc], States};
do_send(_Mod, {_, ok}, Acc, States) ->
    {Acc, States};
do_send(_Mod, {_, {send, []}}, Acc, States) ->
    {Acc, States};
do_send(Mod, {Id, {send, [{unicast, J, Msg}|T]}}, Acc, States) ->
    case lists:keyfind(J, 1, States) of
        false ->
            do_send(Mod, {Id, {send, T}}, Acc, States);
    {J, State} ->
            case Mod:handle_msg(State, Id, Msg) of
                {NewState, Result} ->
                    do_send(Mod, {Id, {send, T}}, [{J, Result}|Acc], lists:keyreplace(J, 1, States, {J, NewState}));
                ignore ->
                    do_send(Mod, {Id, {send, T}}, Acc, States)
            end
    end;
do_send(Mod, {Id, {send, [{multicast, Msg}|T]}}, Acc, States) ->
    Res = lists:map(fun({J, State}) ->
                            case Mod:handle_msg(State, Id, Msg) of
                                {NewState, Result} ->
                                    {{J, NewState}, {J, Result}};
                                ignore ->
                                    {{J, State}, {J, ok}}
                            end
                    end, States),
    {NewStates, Results} = lists:unzip(Res),
    do_send(Mod, {Id, {send, T}}, Results ++ Acc, lists:ukeymerge(1, NewStates, States)).

random_n(N, List) ->
    lists:sublist(shuffle(List), N).

shuffle(List) ->
    [X || {_,X} <- lists:sort([{rand:uniform(), N} || N <- List])].

enumerate(List) ->
    lists:zip(lists:seq(1, length(List)), List).

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

