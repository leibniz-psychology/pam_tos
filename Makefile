all: pam_tos.so

PREFIX:=/
SYSCONFDIR:=${PREFIX}/etc
SECURITYDIR:=${PREFIX}/lib/security

CFLAGS:=-D_FORTIFY_SOURCE=2 -std=c99 -fstack-protector-strong -fPIC -Wall -Wextra -Werror -O2
LDFLAGS:=-Wl,-z,relro,-z,now -Wl,-z,noexecstack
LIBS:=-lldap

pam_tos.so: pam_tos.c
	${CC} ${CFLAGS} ${LDFLAGS} -shared -o $@ $< ${LIBS}

.PHONY: install

install: pam_tos.so pam-tos.conf
	install -d ${SECURITYDIR}
	install -m 755 pam_tos.so ${SECURITYDIR}
	install -d ${SYSCONFDIR}
	install -m 600 pam-tos.conf ${SYSCONFDIR}

