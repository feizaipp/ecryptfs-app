AM_CPPFLAGS = \
	$(DBUS_GLIB_CFLAGS) \
	$(ECRYPTFS_CFLAGS) \
	$(SQLITE3_CFLAGS) \
	-DPACKAGE_LIBEXEC_DIR=\""$(libexecdir)"\"

LIBS = \
	$(DBUS_GLIB_LIBS) \
	$(ECRYPTFS_LIBS) \
	$(SQLITE3_LIBS)

ecryptfsserviceprivdir = $(libexecdir)/ecryptfsservice
ecryptfsservicepriv_PROGRAMS = ecryptfsserviced
ecryptfsserviced_SOURCES = main.c ecryptfsservice.c common.c sqlite_helper.c

BUILT_SOURCES = ecryptfsservice-glue.h

$(BUILT_SOURCES) : org.freedesktop.EcryptfsService.xml
	$(LIBTOOL) --mode=execute dbus-binding-tool --prefix=ecryptfsservice --mode=glib-server \
                        --output=ecryptfsservice-glue.h $(srcdir)/org.freedesktop.EcryptfsService.xml

CLEANFILES = $(BUILT_SOURCES)

EXTRA_DIST = org.freedesktop.EcryptfsService.xml

