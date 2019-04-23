#ifndef __ECRYPTFS_SERVICE_H__
#define __ECRYPTFS_SERVICE_H__

#include <dbus/dbus-glib.h>

typedef struct _EcryptfsService EcryptfsService;
struct _EcryptfsService
{
    GObject parent_instance;
};

typedef struct _EcryptfsServiceClass EcryptfsServiceClass;

struct _EcryptfsServiceClass
{
    GObjectClass parent_class;
};

struct test {
    int x;
};

#define ECRYPTFS_SERVICE_TYPE         (ecryptfs_service_get_type ())
#define ECRYPTFS_SERVICE(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), ECRYPTFS_SERVICE_TYPE, EcryptfsService))
#define IS_ECRYPTFS_SERVICE(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), ECRYPTFS_SERVICE_TYPE))

gboolean ecryptfsservice_test(EcryptfsService *obj, const char *user, int *ret, GError **error);
gboolean ecryptfsservice_create_sbox(EcryptfsService *obj, const char *path, const char *passwd, int *ret, GError **error);
gboolean ecryptfsservice_open_sbox(EcryptfsService *obj, const char *path, const char *passwd, int *ret, GError **error);
gboolean ecryptfsservice_close_sbox(EcryptfsService *obj, const char *path, int *ret, GError **error);
gboolean ecryptfsservice_delete_sbox(EcryptfsService *obj, const char *path, const char *passwd, int *ret, GError **error);
#endif