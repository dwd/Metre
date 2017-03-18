#!/usr/bin/make -f

all: pre-build metre keys
	@echo Done.

OBJS:=$(patsubst src/%.cc,build/src/%.o,$(wildcard src/*.cc))
OBJS+=$(patsubst src/filters/%.cc,build/src/filters/%.o,$(wildcard src/filters/*.cc))
OBJS+=$(patsubst gen/%.cc,build/gen/%.o,$(wildcard gen/*.cc))
TESTOBJS:=$(patsubst tests/%.cc,build/tests/%.o,$(wildcard tests/*.cc))
ETOBJS:=build/src/jid.o build/src/stanza.o build/src/log.o

LIBDIRS=/usr/local/lib
LIBS=event_core unbound ssl event_openssl crypto event_extra icudata icuuc
INCDIRS=include/ ./deps/rapidxml/ ./deps/sigslot/ /usr/local/include

LINKLIBS=$(LIBS:%=-l%)
LINKLIBDIRS=$(LIBDIRS:%=-L%)
FINCDIRS=$(INCDIRS:%=-I%)

pre-build:
  git submodule update --init
  make -C deps/spiffing pre-build
  make -C deps/spiffing gen-ber/.marker

metre-test: $(TESTOBJS) $(ETOBJS)
	@echo [LINK] $+ '=>' $@
	@g++ --std=c++11 -o $@ $+ $(LINKLIBDIRS) $(LINKLIBS)

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
