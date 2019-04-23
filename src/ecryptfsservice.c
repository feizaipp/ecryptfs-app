#include "ecryptfsservice.h"
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include "common.h"

G_DEFINE_TYPE (EcryptfsService, ecryptfs_service, G_TYPE_OBJECT)

gboolean ecryptfsservice_test(EcryptfsService *obj, const char *user, int *ret, GError **error)
{
    if (strcmp(user, "root") == 0)
        *ret = 55;
    else
        *ret = 66;
    return TRUE;
}

gboolean ecryptfsservice_create_sbox(EcryptfsService *obj, const char *path, const char *passwd, int *ret, GError **error)
{
    *ret = create_sbox(path, passwd);
    return TRUE;
}

gboolean ecryptfsservice_open_sbox(EcryptfsService *obj, const char *path, const char *passwd, int *ret, GError **error)
{
    *ret = open_sbox(path, passwd);
    return TRUE;
}

gboolean ecryptfsservice_close_sbox(EcryptfsService *obj, const char *path, int *ret, GError **error)
{
    *ret = close_sbox(path);
    return TRUE;
}

gboolean ecryptfsservice_delete_sbox(EcryptfsService *obj, const char *path, const char *passwd, int *ret, GError **error)
{
    *ret = delete_sbox(path, passwd);
    return TRUE;
}

EcryptfsService *
ecryptfs_service_new (void)
{
    return ECRYPTFS_SERVICE (g_object_new (ECRYPTFS_SERVICE_TYPE, NULL));
}

static void
ecryptfs_service_finalize (GObject *object)
{

}

static void
ecryptfs_service_init (EcryptfsService *monitor)
{

}

static void
ecryptfs_service_class_init (EcryptfsServiceClass *klass)
{

}