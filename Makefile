#!/usr/bin/make -f

all: metre-test metre keys
	@echo Done.

OBJS:=$(patsubst src/%.cpp,build/src/%.o,$(wildcard src/*.cpp))
TESTOBJS:=$(patsubst tests/%.cpp,build/tests/%.o,$(wildcard tests/*.cpp))
ETOBJS:=$(filter-out build/src/dialback.o build/src/mainloop.o,$(OBJS))

LIBDIRS=/usr/local/lib
LIBS=event_core unbound
INCDIRS=include/ ../rapidxml-1.13/ ../SigSlot/ /usr/local/include

LINKLIBS=$(LIBS:%=-l%)
LINKLIBDIRS=$(LIBDIRS:%=-L%)
FINCDIRS=$(INCDIRS:%=-I%)

metre-test: $(TESTOBJS) $(ETOBJS)
	@echo [LINK] $+ '=>' $@
	@g++ --std=c++11 -o $@ $+ $(LINKLIBDIRS) $(LINKLIBS)
	@./$@

metre: $(OBJS)
	@echo [LINK] $< '=>' $@
	g++ --std=c++11 -o $@ $+ $(LINKLIBDIRS) $(LINKLIBS)

build/%.o: %.cpp
	@echo [C++] $< '=>' $@
	@mkdir -p $(dir $@)
	@g++ -g --std=c++11 $(FINCDIRS) -o $@ -c $< -MT $@ -MMD -MF $(patsubst %.o,%.d,$@)

clean:
	@echo [CLEAN] build/ metre metre-test
	@rm -rf build metre metre-test

keys:
	@echo [DNSSEC] . '=>' $@
	@dig . DNSKEY >$@

-include $(wildcard build/src/*.d)
-include $(wildcard build/tests/*.d)
