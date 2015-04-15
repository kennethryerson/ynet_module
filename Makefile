MODULE = ynet
MODVER = 0.7.0
DIST = $(MODULE)_$(MODVER).orig.tar.gz
DESTDIR :=

CC       = gcc
CXX      = g++
RM       = rm -f
RMDIR    = rm -rf
MKDIR    = mkdir -p
CP       = cp -R
CD       = cd
COMPRESS = tar czf
EXTRACT  = tar xf
INSTALL  = install -D

.PHONY : default
default: ynattach plcid

ynattach: ynattach.c
	$(CC) -o $@ $^

plcid: plcid.c
	$(CC) -o $@ $^
	
.PHONY : install
install:
	$(INSTALL) -d $(DESTDIR)/usr/src/$(MODULE)-$(MODVER)
	$(INSTALL) -m644 dkms/* $(DESTDIR)/usr/src/$(MODULE)-$(MODVER)/
	$(INSTALL) -m755 ynattach $(DESTDIR)/sbin/ynattach
	$(INSTALL) -m755 plcid $(DESTDIR)/usr/bin/plcid

.PHONY : dist
dist: $(DIST)

$(DIST): $(MODULE)-$(MODVER)
	$(COMPRESS) $@ $<

.PHONY : deb
deb: $(MODULE)-$(MODVER)
	$(MAKE) -C $(MODULE)-$(MODVER) pkg

.PHONY : pkg
pkg:
	debuild -us -uc -b
	
.PHONY : clean
clean:
	$(RM) $(DIST) *.build *.changes *.deb ynattach plcid
	$(RMDIR) $(MODULE)-$(MODVER)

$(MODULE)-$(MODVER): dkms Makefile ynattach.c plcid.c debian
	$(MKDIR) $@
	$(RMDIR) $@/*
	$(CP) $^ $@/
	
