#!/usr/bin/make -f

all: metre keys
	@echo Done.

OBJS:=$(patsubst src/%.cc,build/src/%.o,$(wildcard src/*.cc))
TESTOBJS:=$(patsubst tests/%.cc,build/tests/%.o,$(wildcard tests/*.cc))
ETOBJS:=$(filter-out build/src/dialback.o build/src/mainloop.o,$(OBJS))

LIBDIRS=/usr/local/lib
LIBS=event_core unbound ssl event_openssl crypto
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

build/%.o: %.cc
	@echo [C++] $< '=>' $@
	@mkdir -p $(dir $@)
	@g++ -g --std=c++11 $(FINCDIRS) -DVALGRIND -o $@ -c $< -MT $@ -MMD -MF $(patsubst %.o,%.d,$@)

clean:
	@echo [CLEAN] build/ metre metre-test
	@rm -rf build metre metre-test

keys:
	@echo [DNSSEC] . '=>' $@
	@dig . DNSKEY >$@

-include $(wildcard build/src/*.d)
-include $(wildcard build/tests/*.d)
