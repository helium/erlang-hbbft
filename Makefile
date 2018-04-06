.PHONY: compile rel test typecheck

REBAR=./rebar3

compile:
	$(REBAR) compile

clean:
	$(REBAR) clean

cover:
	$(REBAR) cover

test: compile
	$(REBAR) eunit

typecheck:
	$(REBAR) dialyzer

