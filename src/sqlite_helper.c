#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <sqlite3.h>
#include <errno.h>
#include <syslog.h>

#define DB_PATH "/etc/secbox.db"

#define CREATE_SECBOX_TABLE \
    "CREATE TABLE secbox_table" \
    "(ID INTEGER primary key autoincrement," \
    "path TEXT," \
    "status INTEGER," \
    "sig TEXT" \
    ")"

#define INSERT_SECBOX_TABLE \
    "INSERT INTO secbox_table" \
    "(path, status, sig)" \
    "VALUES" \
    "(?, ?, ?)"

#define QUERY_STATUS_BY_PATH "SELECT status FROM secbox_table WHERE path=?"
#define QUERY_SIG_BY_PATH "SELECT sig FROM secbox_table WHERE path=?"
#define QUERY_COUNT_BY_PATH "SELECT * FROM secbox_table WHERE path=?"
#define QUERY_TABLE_EXIST "SELECT count(*) FROM sqlite_master WHERE type='table' and name=?"
#define UPDATE_STATUS "UPDATE secbox_table SET status=? WHERE path=?"
#define DELETE_BY_PATH "DELETE FROM secbox_table WHERE path=?"

static sqlite3 *open_db()
{
    int ret;
    sqlite3 *handle = NULL;

    ret = sqlite3_open(DB_PATH, &handle);
    if (ret != SQLITE_OK) {
        syslog(LOG_ERR, "open db (%s) failed.", DB_PATH);
        return NULL;
    }

    return handle;
}

static int close_db(sqlite3 *handle)
{
    if (handle) {
        sqlite3_close(handle);
    }
    return 0;
}

int create_table()
{
    int ret;
    sqlite3 *handle = NULL;

    handle = open_db();
    if (!handle) {
        syslog(LOG_ERR, "sqlite handle (%s) is null", DB_PATH);
        return -EINVAL;
    }
    ret = sqlite3_exec(handle, CREATE_SECBOX_TABLE, NULL, NULL, NULL);
    if (ret != SQLITE_OK) {
        syslog(LOG_ERR, "create table (%s) failed (%d).", CREATE_SECBOX_TABLE), ret;
    }

    ret = close_db(handle);
    return ret;
}

int insert_table(const char *path, int status, const char *sig)
{
    sqlite3_stmt *pstmt = NULL;
    int ret;
    sqlite3 *handle = NULL;

    handle = open_db();
    if (!handle) {
        syslog(LOG_ERR, "sqlite handle (%s) is null", DB_PATH);
        return -EINVAL;
    }
    ret = sqlite3_prepare(handle, INSERT_SECBOX_TABLE, -1, &pstmt, NULL);
    if (ret != SQLITE_OK) {
        syslog(LOG_ERR, "prepare insert table (%s) failed (%d).", INSERT_SECBOX_TABLE, ret);
    }
    ret = sqlite3_bind_text(pstmt, 1, path, -1, SQLITE_STATIC);
    ret = sqlite3_bind_int(pstmt, 2, status);
    ret = sqlite3_bind_text(pstmt, 3, sig, -1, SQLITE_STATIC);
    ret = sqlite3_step(pstmt);
    if (ret != SQLITE_DONE) {
        syslog(LOG_ERR, "insert table (%s) failed (%d).", INSERT_SECBOX_TABLE, ret);
    }

    ret = sqlite3_finalize(pstmt);
    ret = close_db(handle);
    return ret;
}

int query_status_by_path(const char *path, int *status)
{
    sqlite3_stmt *pstmt = NULL;
    int ret;
    sqlite3 *handle = NULL;

    handle = open_db();
    if (!handle) {
        syslog(LOG_ERR, "sqlite handle (%s) is null", DB_PATH);
        return -EINVAL;
    }
    ret = sqlite3_prepare(handle, QUERY_STATUS_BY_PATH, -1, &pstmt, NULL);
    if (ret != SQLITE_OK) {
        syslog(LOG_ERR, "prepare query (%s) failed", QUERY_STATUS_BY_PATH);
    }

    ret = sqlite3_bind_text(pstmt, 1, path, -1, SQLITE_STATIC);

    ret = sqlite3_step(pstmt);
    if (ret == SQLITE_ROW) {
        *status = sqlite3_column_int(pstmt, 0);
    } else {
        syslog(LOG_ERR, "not find path (%s) for status", path);
    }
    ret = sqlite3_finalize(pstmt);
    ret = close_db(handle);
    return ret;
}

int query_sig_by_path(const char *path, char *sig)
{
    sqlite3_stmt *pstmt = NULL;
    int ret;
    sqlite3 *handle = NULL;
    const char *tmp_sig;

    handle = open_db();
    if (!handle) {
        syslog(LOG_ERR, "sqlite handle (%s) is null", DB_PATH);
        return -EINVAL;
    }
    ret = sqlite3_prepare(handle, QUERY_SIG_BY_PATH, -1, &pstmt, NULL);
    if (ret != SQLITE_OK) {
        syslog(LOG_ERR, "prepare query (%s) failed.", QUERY_SIG_BY_PATH);
    }

    ret = sqlite3_bind_text(pstmt, 1, path, -1, SQLITE_STATIC);

    ret = sqlite3_step(pstmt);
    if (ret == SQLITE_ROW) {
        tmp_sig = sqlite3_column_text(pstmt, 0);
        if (tmp_sig && sig) {
            strcpy(sig, tmp_sig);
        }
    } else {
        syslog(LOG_ERR, "not find path (%s) for sig", path);
    }
    ret = sqlite3_finalize(pstmt);
    ret = close_db(handle);
    return ret;
}

int sbox_created(const char *path)
{
    sqlite3_stmt *pstmt = NULL;
    int ret;
    sqlite3 *handle = NULL;
    int num = 0;

    handle = open_db();
    if (!handle) {
        syslog(LOG_ERR, "sqlite handle (%s) is null", DB_PATH);
    }
    ret = sqlite3_prepare(handle, QUERY_COUNT_BY_PATH, -1, &pstmt, NULL);
    if (ret != SQLITE_OK) {
        syslog(LOG_ERR, "prepare query (%s) failed.", QUERY_COUNT_BY_PATH);
    }

    ret = sqlite3_bind_text(pstmt, 1, path, -1, SQLITE_STATIC);

    while (1) {
        ret = sqlite3_step(pstmt);
        if (ret == SQLITE_ROW) {
            num++;
        } else {
            break;
        }
    }

    ret = sqlite3_finalize(pstmt);
    ret = close_db(handle);
    if (num > 0) {
        return 1;
    } else {
        return 0;
    }
}

int table_exist(char *table)
{
    sqlite3_stmt *pstmt = NULL;
    int ret;
    sqlite3 *handle = NULL;
    int exist = 0;

    handle = open_db();
    if (!handle) {
        syslog(LOG_ERR, "sqlite handle (%s) is null", DB_PATH);
    }
    ret = sqlite3_prepare(handle, QUERY_TABLE_EXIST, -1, &pstmt, NULL);
    if (ret != SQLITE_OK) {
        syslog(LOG_ERR, "prepare query (%s) failed.", QUERY_TABLE_EXIST);
    }

    ret = sqlite3_bind_text(pstmt, 1, table, -1, SQLITE_STATIC);

    ret = sqlite3_step(pstmt);
    if ((SQLITE_OK != ret) && (SQLITE_DONE != ret) && (SQLITE_ROW != ret))
    {
        exist = 1;
        goto out;
    }

    exist = sqlite3_column_int(pstmt, 0);

out:
    ret = sqlite3_finalize(pstmt);
    ret = close_db(handle);

    return exist;
}

int modify_status_by_path(const char *path, int status)
{
    sqlite3_stmt *pstmt = NULL;
    int ret;
    sqlite3 *handle = NULL;

    handle = open_db();
    if (!handle) {
        syslog(LOG_ERR, "sqlite handle (%s) is null", DB_PATH);
        return -EINVAL;
    }
    ret = sqlite3_prepare(handle, UPDATE_STATUS, -1, &pstmt, NULL);
    if (ret != SQLITE_OK) {
        syslog(LOG_ERR, "prepare query (%s) failed.", UPDATE_STATUS);
    }

    ret = sqlite3_bind_int(pstmt, 1, status);
    ret = sqlite3_bind_text(pstmt, 2, path, -1, SQLITE_STATIC);

    ret = sqlite3_step(pstmt);
    ret = sqlite3_finalize(pstmt);
    ret = close_db(handle);
    return ret;
}

int delete_by_path(const char *path)
{
    sqlite3_stmt *pstmt = NULL;
    int ret;
    sqlite3 *handle = NULL;

    handle = open_db();
    if (!handle) {
        syslog(LOG_ERR, "sqlite handle (%s) is null", DB_PATH);
        return -EINVAL;
    }
    ret = sqlite3_prepare(handle, DELETE_BY_PATH, -1, &pstmt, NULL);
    if (ret != SQLITE_OK) {
        syslog(LOG_ERR, "prepare query (%s) failed.", DELETE_BY_PATH);
    }

    ret = sqlite3_bind_text(pstmt, 1, path, -1, SQLITE_STATIC);

    ret = sqlite3_step(pstmt);
    ret = sqlite3_finalize(pstmt);
    ret = close_db(handle);
    return ret;
}

int sbox_opened(const char *path)
{
    int status;

    query_status_by_path(path, &status);

    return status;
}
