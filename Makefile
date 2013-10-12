#!/usr/bin/make -f

all: eloquence-test eloquence
	@echo Done.

OBJS:=$(patsubst src/%.cpp,build/src/%.o,$(wildcard src/*.cpp))
TESTOBJS:=$(patsubst tests/%.cpp,build/tests/%.o,$(wildcard tests/*.cpp))
ETOBJS:=$(filter-out build/src/mainloop.o,$(OBJS))

eloquence-test: $(TESTOBJS) $(ETOBJS)
	@echo [LINK] $+ '=>' $@
	@g++ --std=c++11 -lzmq -o $@ $+
	@./$@

eloquence: $(OBJS)
	@echo [LINK] $< '=>' $@
	@g++ --std=c++11 -lzmq -o $@ $+

build/%.o: %.cpp
	@echo [C++] $< '=>' $@
	@mkdir -p $(dir $@)
	@g++ -g --std=c++11 -Iinclude/ -I../rapidxml-1.13/ -o $@ -c $< -MT $@ -MMD -MF $(patsubst %.o,%.d,$@)

-include $(wildcard build/src/*.d)
-include $(wildcard build/tests/*.d)
