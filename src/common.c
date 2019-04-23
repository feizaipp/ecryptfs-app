#include "common.h"
#include <sys/types.h>
#include <unistd.h>
#include <syslog.h>
#include <ecryptfs.h>
#include <errno.h>
#include <sys/wait.h>
#include "sqlite_helper.h"
#include <stdlib.h>
#include <stdio.h>
#include <mntent.h>

#define DEFAULT_CIPHER "aes"
#define DEFAULT_KEY_BYTES "16"
#define MOUNT_OPTS "ecryptfs_sig=%s,ecryptfs_cipher=%s,ecryptfs_key_bytes=%s,ecryptfs_unlink_sigs,rw"

static int ecryptfs_mount(const char *source, const char *target, char *opts)
{
	pid_t pid, pid_child;
	int rc, status;

	if (!source) {
		rc = -EINVAL;
		syslog(LOG_ERR, "Invalid source directory\n");
		goto out;
	}

	if (!target) {
 		rc = -EINVAL;
 		syslog(LOG_ERR, "Invalid target directory\n");
 		goto out;
	}

	pid = fork();
	if (pid == -1) {
		syslog(LOG_ERR, "Could not fork process to mount eCryptfs: [%d]\n", -errno);
		rc = -errno;
	} else if (pid == 0) {
 		execl("/bin/mount", "mount", "-i", "--no-canonicalize", "-t", "ecryptfs", source, target, "-o", opts, NULL);

		/* error message shown in console to let users know what was wrong */
		/* i.e. /bin/mount does not exist */
		perror("Failed to execute /bin/mount command");
		exit(errno);
	} else {
		pid_child = waitpid(pid, &status, 0);
		if (pid_child == -1) {
			syslog(LOG_ERR, "Failed waiting for /bin/mount process: [%d]\n", -errno);
			rc = -errno;
			goto out;
		}

		rc = -EPERM;
		if (WIFEXITED(status))
			rc = -WEXITSTATUS(status);

		if (rc) {
			syslog(LOG_ERR, "Failed to perform eCryptfs mount: [%d]\n", rc);
			if (-EPIPE == rc) {
				rc = -EPERM;
			}
		}
	}

out:

	return rc;
}

static int get_mount_opt_value(char *mnt_opts, char *name, char **value)
{
	char *name_start, *val_start, *val_stop;
	size_t name_len, val_len;
	int rc = 0;

	name_len = strlen(name);
	if (name[name_len - 1] != '=') {
		rc = EINVAL;
		goto out;
	}

	name_start = strstr(mnt_opts, name);
	if (!name_start) {
		rc = EINVAL;
		goto out;
	}

	val_start = name_start + name_len;
	val_stop = strstr(val_start, ",");
	if (!val_stop)
		val_stop = mnt_opts + strlen(mnt_opts);

	val_len = val_stop - val_start;
	*value = malloc(val_len + 1);
	if (!(*value)) {
		rc = ENOMEM;
		goto out;
	}
	memcpy(*value, val_start, val_len);
	(*value)[val_len] = '\0';
out:
	return rc;
}

static int unlink_keys_from_keyring(const char *mnt_point)
{
	struct mntent *mntent;
	FILE *file;
	char *fekek_sig = NULL, *fnek_sig = NULL;
	int fekek_fail = 0, fnek_fail = 0;
	int rc;

	file = setmntent("/etc/mtab", "r");
	if (!file) {
		rc = EINVAL;
		goto out;
	}
	while ((mntent = getmntent(file))) {
		if (strcmp("ecryptfs", mntent->mnt_type))
			continue;
		if (strcmp(mnt_point, mntent->mnt_dir))
			continue;
		break;
	}
	if (!mntent) {
		rc = EINVAL;
		goto end_out;
	}
	if (!hasmntopt(mntent, "ecryptfs_unlink_sigs")) {
		rc = 0;
		goto end_out;
	}
	rc = get_mount_opt_value(mntent->mnt_opts, "ecryptfs_sig=", &fekek_sig);
	if (!rc) {
		fekek_fail = ecryptfs_remove_auth_tok_from_keyring(fekek_sig);
		if (fekek_fail == ENOKEY)
			fekek_fail = 0;
		if (fekek_fail)
			fprintf(stderr, "Failed to remove fekek with sig [%s] "
				"from keyring: %s\n", fekek_sig,
				strerror(fekek_fail));
	} else {
		fekek_fail = rc;
	}
	if (!get_mount_opt_value(mntent->mnt_opts,
				 "ecryptfs_fnek_sig=", &fnek_sig)
	    && strcmp(fekek_sig, fnek_sig)) {
		fnek_fail = ecryptfs_remove_auth_tok_from_keyring(fnek_sig);
		if (fnek_fail == ENOKEY)
			fnek_fail = 0;
		if (fnek_fail) {
			fprintf(stderr, "Failed to remove fnek with sig [%s] "
				"from keyring: %s\n", fnek_sig, 
				strerror(fnek_fail));
		}
	}
	free(fekek_sig);
	free(fnek_sig);
end_out:
	endmntent(file);
out:
	return (fekek_fail ? fekek_fail : (fnek_fail ? fnek_fail : rc));
}

static int ecryptfs_umount(const char *target)
{
	pid_t pid, pid_child;
	int rc, status;

	if (!target) {
 		rc = -EINVAL;
 		syslog(LOG_ERR, "Invalid target directory\n");
 		goto out;
	}

    if (unlink_keys_from_keyring(target))
		syslog(LOG_ERR, "Could not unlink the key(s) from your keying. "
			"Please use `keyctl unlink` if you wish to remove the "
			"key(s). Proceeding with umount.\n");

	pid = fork();
	if (pid == -1) {
		syslog(LOG_ERR, "Could not fork process to umount eCryptfs: [%d]\n", -errno);
		rc = -errno;
	} else if (pid == 0) {
 		execl("/bin/umount", "umount", "-i", target, NULL);

		/* error message shown in console to let users know what was wrong */
		/* i.e. /bin/umount does not exist */
		perror("Failed to execute /bin/umount command");
		exit(errno);
	} else {
		pid_child = waitpid(pid, &status, 0);
		if (pid_child == -1) {
			syslog(LOG_ERR, "Failed waiting for /bin/umount process: [%d]\n", -errno);
			rc = -errno;
			goto out;
		}

		rc = -EPERM;
		if (WIFEXITED(status))
			rc = -WEXITSTATUS(status);

		if (rc) {
			syslog(LOG_ERR, "Failed to perform eCryptfs umount: [%d]\n", rc);
			if (-EPIPE == rc) {
				rc = -EPERM;
			}
		}
	}

out:

	return rc;
}

int create_sbox(const char *path, const char *passwd)
{
	char salt[ECRYPTFS_SALT_SIZE];
	char *salt_hex = ECRYPTFS_DEFAULT_SALT_HEX;
	char *auth_tok_sig;
    int rc = 0;
    char mnt_param[128];

	if (sbox_created(path)) {
		syslog(LOG_ERR, "sbox (%s) already created", path);
		rc = SBOX_CREATED;
		goto out;
	}

    auth_tok_sig = malloc(ECRYPTFS_SIG_SIZE_HEX + 1);
	if (!auth_tok_sig) {
		rc = -ENOMEM;
		goto out;
	}
    from_hex(salt, salt_hex, ECRYPTFS_SIG_SIZE);
    rc = ecryptfs_add_passphrase_key_to_keyring(auth_tok_sig, passwd, salt);
	if (rc < 0) {
		free(auth_tok_sig);
		goto out;
	}
    snprintf(mnt_param, sizeof(mnt_param), MOUNT_OPTS, auth_tok_sig, DEFAULT_CIPHER, DEFAULT_KEY_BYTES);

    rc = ecryptfs_mount(path, path, mnt_param);
    if (rc) {
        syslog(LOG_ERR, "ecryptfs_mount (%s) error (%d)", path, rc);
		free(auth_tok_sig);
		goto out;
    } else {
		insert_table(path, 0, auth_tok_sig);
	}
    rc = ecryptfs_umount(path);
	free(auth_tok_sig);
out:
    return rc;
}

int open_sbox(const char *path, const char *passwd)
{
	char salt[ECRYPTFS_SALT_SIZE];
	char *salt_hex = ECRYPTFS_DEFAULT_SALT_HEX;
	char *auth_tok_sig;
    int rc = 0;
    char mnt_param[128];
	char fekek[ECRYPTFS_MAX_KEY_BYTES];
	struct ecryptfs_auth_tok *auth_tok = NULL;
	char *sig = NULL;

	if (!sbox_created(path)) {
		syslog(LOG_ERR, "sbox (%s) not created", path);
		rc = SBOX_NCREATED;
		goto out;
	}

	if (sbox_opened(path)) {
		syslog(LOG_ERR, "sbox (%s) already opened", path);
		rc = SBOX_OPENED;
		goto out;
	}

    auth_tok_sig = malloc(ECRYPTFS_SIG_SIZE_HEX + 1);
	if (!auth_tok_sig) {
		rc = -ENOMEM;
		goto out;
	}
	sig = malloc(ECRYPTFS_SIG_SIZE_HEX + 1);
	if (!sig) {
		rc = -ENOMEM;
		goto out_auth_tok_sig;
	}
    from_hex(salt, salt_hex, ECRYPTFS_SIG_SIZE);
    rc = ecryptfs_generate_passphrase_auth_tok(&auth_tok, auth_tok_sig,
						   fekek, salt, passwd);
	if (rc) {
		syslog(LOG_ERR, "%s: Error attempting to generate the "
		       "passphrase auth tok payload; rc = [%d]\n",
		       __FUNCTION__, rc);
		goto out_sig;
	}

	rc = query_sig_by_path(path, sig);
	if (rc) {
		syslog(LOG_ERR, "query sig failed, path(%s)\n", path);
		goto out_auth_tok;
	}

	if (strcmp(sig, auth_tok_sig)) {
		rc = SBOX_PASSWD_ERR;
		goto out_auth_tok;
	}

	rc = ecryptfs_add_auth_tok_to_keyring(auth_tok, auth_tok_sig);
	if (rc < 0) {
		syslog(LOG_ERR, "%s: Error adding auth tok with sig [%s] to "
		       "the keyring; rc = [%d]\n", __FUNCTION__, auth_tok_sig,
		       rc);
		goto out_auth_tok;
	}
    snprintf(mnt_param, sizeof(mnt_param), MOUNT_OPTS, auth_tok_sig, DEFAULT_CIPHER, DEFAULT_KEY_BYTES);

    rc = ecryptfs_mount(path, path, mnt_param);
    if (rc) {
        syslog(LOG_ERR, "ecryptfs_mount (%s) error (%d)", path, rc); 
    } else {
		modify_status_by_path(path, 1);
	}

out_auth_tok:
	if (auth_tok) {
		memset(auth_tok, 0, sizeof(*auth_tok));
		free(auth_tok);
	}
out_sig:
	if (sig) {
		free(sig);
	}
out_auth_tok_sig:
	if (auth_tok_sig) {
		free(auth_tok_sig);
	}
out:
    return rc;
}

int close_sbox(const char *path)
{
    int rc = 0;

	if (!sbox_created(path)) {
		syslog(LOG_ERR, "sbox (%s) not created", path);
		rc = SBOX_NCREATED;
		goto out;
	}

	if (!sbox_opened(path)) {
		syslog(LOG_ERR, "sbox (%s) already closed", path);
		rc = SBOX_NOPENED;
		goto out;
	}

    rc = ecryptfs_umount(path);
    if (rc) {
        syslog(LOG_ERR, "ecryptfs_umount (%s) error (%d)", path, rc); 
    } else {
		modify_status_by_path(path, 0);
	}
out:
    return rc;
}

int delete_sbox(const char *path, const char *passwd)
{
    int rc = 0;
	char cmd[256];
	char salt[ECRYPTFS_SALT_SIZE];
	char *salt_hex = ECRYPTFS_DEFAULT_SALT_HEX;
	char *auth_tok_sig;
	char fekek[ECRYPTFS_MAX_KEY_BYTES];
	struct ecryptfs_auth_tok *auth_tok = NULL;
	char *sig = NULL;

	if (!sbox_created(path)) {
		syslog(LOG_ERR, "sbox (%s) not exist", path);
		rc = SBOX_NCREATED;
		goto out;
	}

	auth_tok_sig = malloc(ECRYPTFS_SIG_SIZE_HEX + 1);
	if (!auth_tok_sig) {
		rc = -ENOMEM;
		goto out;
	}
	sig = malloc(ECRYPTFS_SIG_SIZE_HEX + 1);
	if (!sig) {
		rc = -ENOMEM;
		goto out_auth_tok_sig;
	}
    from_hex(salt, salt_hex, ECRYPTFS_SIG_SIZE);
    rc = ecryptfs_generate_passphrase_auth_tok(&auth_tok, auth_tok_sig,
						   fekek, salt, passwd);
	if (rc) {
		syslog(LOG_ERR, "%s: Error attempting to generate the "
		       "passphrase auth tok payload; rc = [%d]\n",
		       __FUNCTION__, rc);
		goto out_sig;
	}

	rc = query_sig_by_path(path, sig);
	if (rc) {
		syslog(LOG_ERR, "query sig failed, path(%s)\n", path);
		goto out_auth_tok;
	}

	if (strcmp(sig, auth_tok_sig)) {
		rc = SBOX_PASSWD_ERR;
		goto out_auth_tok;
	}

	if (sbox_opened(path)) {
		rc = close_sbox(path);
	}

	/* rm */
	snprintf(cmd, sizeof(cmd), "rm -rf %s", path);
	system(cmd);

	/* sqlite update */
	delete_by_path(path);

out_auth_tok:
	if (auth_tok) {
		memset(auth_tok, 0, sizeof(*auth_tok));
		free(auth_tok);
	}
out_sig:
	if (sig) {
		free(sig);
	}
out_auth_tok_sig:
	if (auth_tok_sig) {
		free(auth_tok_sig);
	}
out:
    return rc;
}

int create_tables()
{
	if (!table_exist("secbox_table")) {
		create_table();
	}
}
