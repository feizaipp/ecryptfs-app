#ifndef _COMMON_H
#define _COMMON_H

#define SBOX_OK 0
#define SBOX_CREATED 1
#define SBOX_OPENED 2
#define SBOX_NCREATED 3
#define SBOX_NOPENED 4
#define SBOX_PASSWD_ERR 5

int create_sbox(const char *path, const char *passwd);
int open_sbox(const char *path, const char *passwd);
int close_sbox(const char *path);
int delete_sbox(const char *path, const char *passwd);
int create_tables();
#endif