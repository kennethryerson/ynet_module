MODULE = ynet
MODVER = 0.1.0
DIST = $(MODULE)_$(MODVER).orig.tar.gz
DESTDIR :=

CC       = gcc
CXX      = g++
RM       = rm -f
RMDIR    = rm -rf
MKDIR    = mkdir
CP       = cp -R
CD       = cd
COMPRESS = tar czf
EXTRACT  = tar xf
INSTALL  = install -D

.PHONY : default
default: ynattach

ynattach: ynattach.c
	$(CC) -o $@ $^
	
.PHONY : install
install:
	$(INSTALL) -d $(DESTDIR)/usr/src/$(MODULE)-$(MODVER)
	$(INSTALL) -m644 dkms/* $(DESTDIR)/usr/src/$(MODULE)-$(MODVER)/
	$(INSTALL) -m755 ynattach $(DESTDIR)/sbin/ynattach

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
	$(RM) $(DIST) *.build *.changes *.deb ynattach
	$(RMDIR) $(MODULE)-$(MODVER)

$(MODULE)-$(MODVER): dkms Makefile ynattach.c debian
	$(MKDIR) $@
	$(RMDIR) $@/*
	$(CP) $^ $@/
	
