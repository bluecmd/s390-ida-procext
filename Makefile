IDASDK ?= $(HOME)/idasdk75/
IDA ?= /opt/idapro-7.5/

CFLAGS=\
		-m64 -std=c++11 -g -pipe -I $(IDASDK)/include/ \
		-DNO_OBSOLETE_FUNCS -D_DEBUG -D_GLIBCXX_USE_CXX11_ABI=0 \
		-fPIC -fdiagnostics-show-option -fno-diagnostics-show-caret \
		-fno-strict-aliasing -fvisibility=hidden -fwrapv -Wall \
		-Werror=format-nonliteral -Werror=format-security -Wextra \
		-Wformat=2 -Wimplicit-fallthrough=0 -Wshadow -Wunused -Wno-format-y2k \
		-Wno-missing-field-initializers -Wno-sign-compare -Wno-unused-local-typedefs \
		-pthread -fvisibility-inlines-hidden -Wno-class-memaccess \
		-Wno-invalid-offsetof -fno-rtti

LDFLAGS=\
		-m64 --shared -Wl,--no-undefined \
		-L$(IDASDK)/lib/x64_linux_gcc_64/ \
		-lida64 -Wl,--build-id -Wl,--gc-sections -Wl,--warn-shared-textrel \
		-Wl,--version-script=$(IDASDK)/plugins/exports.def \
		-lrt -lpthread -lc

SOURCES := s390.cpp

.PHONY: all clean

all: s390ext64.so s390ext.so

obj:
	mkdir -p obj

obj/%.o32: %.cpp obj
	g++ $(CFLAGS) -D__LINUX__ -c -o "$@" "$<"

obj/%.o64: %.cpp obj
	g++ $(CFLAGS) -D __EA64__ -D__LINUX__ -c -o "$@" "$<"

s390ext.so: $(patsubst %.cpp,obj/%.o32,$(SOURCES))
	g++ -Wl,-Map,"obj/$@.map" "$<" $(LDFLAGS) -o "$@"

s390ext64.so: $(patsubst %.cpp,obj/%.o64,$(SOURCES))
	g++ -Wl,-Map,"obj/$@.map" "$<" $(LDFLAGS) -o "$@"

install: s390ext64.so s390ext.so
	cp -v -f s390ext.so "$(IDA)/plugins/"
	cp -v -f s390ext64.so "$(IDA)/plugins/"

clean:
	\rm -fr obj/
