.PHONY: compile rel typecheck

REBAR=./rebar3

compile:
	$(REBAR) compile

clean:
	$(REBAR) clean

typecheck:
	$(REBAR) dialyzer

doc:
	$(REBAR) edoc
