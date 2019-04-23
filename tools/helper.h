#ifndef __HELPER_H
#define __HELPER_H

#define CONV_ECHO_ON  1                            /* types of echo state */
#define CONV_ECHO_OFF 0

#define SBOX_OK 0
#define SBOX_CREATED 1
#define SBOX_OPENED 2
#define SBOX_NCREATED 3
#define SBOX_NOPENED 4
#define SBOX_PASSWD_ERR 5

int read_usbkey_pin_password(int echo, const char *prompt, char **retstr);

#endif