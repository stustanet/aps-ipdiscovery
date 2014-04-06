# compiler and linker
CC = gcc
SRC = ip_discovery.c
OBJ = ${SRC:.c=.o}

# paths
PREFIX = /usr/local

# includes and libs
INCS = -I. -I/usr/include
LIBS = -L/usr/lib -lc

#CFLAGS = -g -pedantic -Wall -O0 ${INCS} ${CPPFLAGS}
CFLAGS = -pedantic -Wall -Os ${INCS}
#LDFLAGS = -g ${LIBS}
LDFLAGS = -s ${LIBS}

all: ip_discovery

options:
	@echo build options:
	@echo "CFLAGS   = ${CFLAGS}"
	@echo "LDFLAGS  = ${LDFLAGS}"
	@echo "CC       = ${CC}"

.c.o:
	@echo CC $<
	@${CC} -c ${CFLAGS} $<

${OBJ}:

ip_discovery: ${OBJ}
	@echo CC -o $@
	@${CC} -o $@ ${OBJ} ${LDFLAGS}

clean:
	@echo cleaning
	@rm -f ip_discovery ${OBJ}

install: all
	@echo installing executable file to ${DESTDIR}${PREFIX}/bin
	@mkdir -p ${DESTDIR}${PREFIX}/bin
	@cp -f ip_discovery ${DESTDIR}${PREFIX}/bin
	@chmod 755 ${DESTDIR}${PREFIX}/bin/ip_discovery

uninstall:
	@echo removing executable file from ${DESTDIR}${PREFIX}/bin
	@rm -f ${DESTDIR}${PREFIX}/bin/ip_discovery

.PHONY: all options clean install uninstall
