#ifndef __SQLITE_HELPER_
#define __SQLITE_HELPER_

#include <sqlite3.h>

int create_table();
int insert_table(const char *path, int status, const char *sig);
int query_status_by_path(const char *path, int *status);
int query_sig_by_path(const char *path, char *sig);
int sbox_created(const char *path);
int table_exist(char *table);
int modify_status_by_path(const char *path, int status);
int delete_by_path(const char *path);
int sbox_opened(const char *path);

#endif