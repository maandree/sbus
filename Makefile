.POSIX:

CONFIGFILE = config.mk
include $(CONFIGFILE)

LIBSBUS_MAJOR = 1
LIBSBUS_MINOR = 0

LIBSBUSD_MAJOR = 1
LIBSBUSD_MINOR = 0

all: sbusd libsbus.so libsbus.a libsbusd.so libsbusd.a test

sbusd.o: arg.h libsbusd.h
libsbus.o: libsbus.h
test.o: libsbus.h
test: test.o libsbus.a
sbusd: sbusd.o libsbusd.a

.o.a:
	$(AR) rc $@ $?
	$(AR) -s $@

libsbus.so: libsbus.a
	$(CC) -shared -Wl,-soname,$@.$(LIBSBUS_MAJOR) -o $@ $^ $(LDFLAGS)

libsbusd.so: libsbusd.a
	$(CC) -shared -Wl,-soname,$@.$(LIBSBUSD_MAJOR) -o $@ $^ $(LDFLAGS)

check: test sbusd
	./test

install: sbusd libsbus.a libsbus.so libsbusd.a libsbusd.so
	mkdir -p -- "$(DESTDIR)$(PREFIX)/bin"
	mkdir -p -- "$(DESTDIR)$(PREFIX)/lib"
	mkdir -p -- "$(DESTDIR)$(PREFIX)/share/licenses/sbus"
	cp -- sbusd "$(DESTDIR)$(PREFIX)/bin/"
	cp -- libsbus.a "$(DESTDIR)$(PREFIX)/lib/"
	cp -- libsbus.so "$(DESTDIR)$(PREFIX)/lib/libsbus.so.$(LIBSBUS_MAJOR)"
	ln -sf -- libsbus.so.$(LIBSBUS_MAJOR) "$(DESTDIR)$(PREFIX)/lib/libsbus.so"
	ln -sf -- libsbus.so.$(LIBSBUS_MAJOR) "$(DESTDIR)$(PREFIX)/lib/libsbus.so.$(LIBSBUS_MAJOR).$(LIBSBUS_MINOR)"
	cp -- libsbusd.a "$(DESTDIR)$(PREFIX)/lib/"
	cp -- libsbusd.so "$(DESTDIR)$(PREFIX)/lib/libsbusd.so.$(LIBSBUSD_MAJOR)"
	ln -sf -- libsbusd.so.$(LIBSBUSD_MAJOR) "$(DESTDIR)$(PREFIX)/lib/libsbusd.so"
	ln -sf -- libsbusd.so.$(LIBSBUSD_MAJOR) "$(DESTDIR)$(PREFIX)/lib/libsbusd.so.$(LIBSBUSD_MAJOR).$(LIBSBUSD_MINOR)"
	cp -- LICENSE "$(DESTDIR)$(PREFIX)/share/licenses/sbus/"

uninstall:
	-rm -f -- "$(DESTDIR)$(PREFIX)/bin/sbusd"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libsbus.a"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libsbus.so"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libsbus.so.$(LIBSBUS_MAJOR)"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libsbus.so.$(LIBSBUS_MAJOR).$(LIBSBUS_MINOR)"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libsbusd.a"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libsbusd.so"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libsbusd.so.$(LIBSBUSD_MAJOR)"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libsbusd.so.$(LIBSBUSD_MAJOR).$(LIBSBUSD_MINOR)"
	-rm -rf -- "$(DESTDIR)$(PREFIX)/share/licenses/sbus"

clean:
	-rm -f -- sbusd test *.o *.so *.a .test.sock .test.pid

.PHONY: all check install uninstall clean
