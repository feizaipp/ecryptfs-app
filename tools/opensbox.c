#include <dbus/dbus-glib.h>
#include <stdio.h>
#include <stdlib.h>
#include "helper.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

static int dir_exists(const char *path)
{
    struct stat buf;

    if (stat(path, &buf) < 0)
        return 0;
    return S_ISDIR(buf.st_mode);
}

static analysis_ret(char *argv, int ret)
{
    switch (ret) {
        case SBOX_OK:
            printf("%s ok.\n", argv);
            break;
        case SBOX_CREATED:
            printf("sbox already created.\n");
            break;
        case SBOX_OPENED:
            printf("sbox already opend.\n");
            break;
        case SBOX_NCREATED:
            printf("sbox not created yet.\n");
            break;
        case SBOX_NOPENED:
            printf("sbox not opened yet.\n");
            break;
        case SBOX_PASSWD_ERR:
            printf("password error.\n");
            break;
        default:
            printf("unknow error.\n");
            break;
    }
}

static void Usage(char *argv)
{
    printf("%s <path>\n", argv);
}

int main (int argc, char **argv)
{
    DBusGConnection *bus;
    DBusGProxy *remote_object;
    DBusGProxy *remote_object_introspectable;
    GError *error = NULL;
    char *introspect_data;
    guint i;
    gint ret;
    char *passwd = NULL;
    char *path = NULL;

    //g_type_init ();
    {
        GLogLevelFlags fatal_mask;

        fatal_mask = g_log_set_always_fatal (G_LOG_FATAL_MASK);
        fatal_mask |= G_LOG_LEVEL_WARNING | G_LOG_LEVEL_CRITICAL;
        g_log_set_always_fatal (fatal_mask);
    }

    if (argc != 2) {
        Usage(argv[0]);
        exit(0);
    }

    if (!dir_exists(argv[1])) {
        printf("path (%s) dir not exist", argv[1]);
		exit(0);
    }

    path = realpath(argv[1], NULL);
    if (!path) {
		printf("realpath failed, source %s [%d]", argv[1], -errno);
		exit(0);
	}

    bus = dbus_g_bus_get (DBUS_BUS_SYSTEM, &error);
    if (!bus)
        printf ("Couldn't connect to system bus", error);

    remote_object = dbus_g_proxy_new_for_name (bus,
                            "org.freedesktop.EcryptfsService",
                            "/org/freedesktop/EcryptfsService",
                            "org.freedesktop.EcryptfsService.Base");

    ret = read_usbkey_pin_password(CONV_ECHO_OFF, "Enter Password: ", &passwd);
    if (ret < 0) {
        printf("Read Password failed.\n");
        return -1;
    }
    if (!dbus_g_proxy_call (remote_object, "OpenSbox", &error,
                G_TYPE_STRING, path, G_TYPE_STRING, passwd, G_TYPE_INVALID,
                G_TYPE_INT, &ret, G_TYPE_INVALID))
        printf ("Failed to call OpenSbox (%s).\n", error->message);
    analysis_ret(argv[0], ret);
    g_object_unref (G_OBJECT (remote_object));
    free(path);

    exit(0);
}
