.POSIX:

LIB_MAJOR = 1
LIB_MINOR = 0

CONFIGFILE = config.mk
include $(CONFIGFILE)

all: sbusd libsbus.so libsbus.a test

sbusd.o: arg.h libsbusd.h
libsbus.o: libsbus.h
test.o: libsbus.h
test: test.o libsbus.a
sbusd: sbusd.o libsbusd.o

libsbus.so: libsbus.o
	$(CC) -shared -Wl,-soname,libsbus.so.$(LIB_MAJOR) -o $@ $^ $(LDFLAGS)

libsbus.a: libsbus.o
	$(AR) rc $@ $?
	$(AR) -s $@

check: test sbusd
	./test

install: sbusd libsbus.a libsbus.so
	mkdir -p -- "$(DESTDIR)$(PREFIX)/bin"
	mkdir -p -- "$(DESTDIR)$(PREFIX)/lib"
	mkdir -p -- "$(DESTDIR)$(PREFIX)/share/licenses/sbus"
	cp -- sbusd "$(DESTDIR)$(PREFIX)/bin/"
	cp -- libsbus.a "$(DESTDIR)$(PREFIX)/lib/"
	cp -- libsbus.so "$(DESTDIR)$(PREFIX)/lib/libsbus.so.$(LIB_MAJOR)"
	ln -sf -- libsbus.so.$(LIB_MAJOR) "$(DESTDIR)$(PREFIX)/lib/libsbus.so"
	ln -sf -- libsbus.so.$(LIB_MAJOR) "$(DESTDIR)$(PREFIX)/lib/libsbus.so.$(LIB_MAJOR).$(LIB_MINOR)"
	cp -- LICENSE "$(DESTDIR)$(PREFIX)/share/licenses/sbus/"

uninstall:
	-rm -f -- "$(DESTDIR)$(PREFIX)/bin/sbusd"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libsbus.a"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libsbus.so"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libsbus.so.$(LIB_MAJOR)"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libsbus.so.$(LIB_MAJOR).$(LIB_MINOR)"
	-rm -rf -- "$(DESTDIR)$(PREFIX)/share/licenses/sbus"

clean:
	-rm -f -- sbusd test *.o *.so *.a .test.sock .test.pid

.PHONY: all check install uninstall clean
