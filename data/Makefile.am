
NULL =

dbusservicedir       = $(datadir)/dbus-1/system-services
dbusservice_in_files = org.freedesktop.EcryptfsService.service.in
dbusservice_DATA     = $(dbusservice_in_files:.service.in=.service)

$(dbusservice_DATA): $(dbusservice_in_files) Makefile
	@sed -e "s|\@ecryptfsserviceprivdir\@|$(libexecdir)/ecryptfsservice|" $< > $@

dbusconfdir = $(sysconfdir)/dbus-1/system.d
dbusconf_in_files = org.freedesktop.EcryptfsService.conf.in
dbusconf_DATA = $(dbusconf_in_files:.conf.in=.conf)

$(dbusconf_DATA): $(dbusconf_in_files) Makefile
	cp $< $@

systemdservice_in_files = ecryptfsservice.service.in

if HAVE_SYSTEMD
systemdservicedir       = $(systemdsystemunitdir)
systemdservice_DATA     = $(systemdservice_in_files:.service.in=.service)

$(systemdservice_DATA): ecryptfsservice.service.in Makefile
	@sed -e "s|\@ecryptfsserviceprivdir\@|$(libexecdir)/ecryptfsservice|" ecryptfsservice.service.in > ecryptfsservice.service
endif


EXTRA_DIST =                                                                   \
	org.freedesktop.EcryptfsService.xml                                            \
	$(systemdservice_in_files)                                             \
	$(dbusservice_in_files)                                                \
	$(dbusconf_in_files)                                                   \
	$(NULL)

clean-local:
	rm -f *~                                                               \
	$(dbusservice_DATA)                                                    \
	$(dbusconf_DATA)                                                       \
	$(systemdservice_DATA)
