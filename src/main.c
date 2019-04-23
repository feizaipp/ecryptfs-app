#include "ecryptfsservice.h"
#include <stdio.h>
#include "ecryptfsservice-glue.h"
#include "common.h"

int main(int argc, char **argv)
{
    GMainLoop *mainLoop;
    DBusGConnection *bus;
    GError *error = NULL;
    DBusGProxy *bus_proxy;
    EcryptfsService *ecryptfs_service;
    guint request_name_result;

    dbus_g_object_type_install_info(ECRYPTFS_SERVICE_TYPE, &dbus_glib_ecryptfsservice_object_info);
    mainLoop = g_main_loop_new(NULL, FALSE);
    bus = dbus_g_bus_get(DBUS_BUS_SYSTEM, &error);
    if (!bus) {
        printf("Cannot get system bus %s\n.", error->message);
        return 1;
    }
    bus_proxy = dbus_g_proxy_new_for_name(bus, "org.freedesktop.DBus", 
                                                                "/org/freedesktop/DBus", "org.freedesktop.DBus");
    if (!dbus_g_proxy_call(bus_proxy, "RequestName", 
                                    &error, G_TYPE_STRING, 
                                    "org.freedesktop.EcryptfsService", G_TYPE_UINT, 0,
			                        G_TYPE_INVALID, G_TYPE_UINT, &request_name_result,
			                        G_TYPE_INVALID)) {
        printf("Failed to acquire org.freedesktop.EcryptfsService %s.\n", error->message);
        return 1;
    }
    // new object
    ecryptfs_service = ecryptfs_service_new();
    dbus_g_connection_register_g_object(bus, "/org/freedesktop/EcryptfsService", G_OBJECT(ecryptfs_service));
    printf ("EcryptfsService server is running\n");
    create_tables();
    g_main_loop_run(mainLoop);
    g_object_unref(bus_proxy);
    return 0;
}