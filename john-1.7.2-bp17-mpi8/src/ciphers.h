/* 
 * In this file you can change the compiled-in cipher support
 */

/* Standard DES */
//#define CIPHER_DES

/* BSDI DES */
//#define CIPHER_BSDI

/* Standard UNIX MD5 as used on FreeBSD and modern linux */
//#define CIPHER_MD5

/* UNIX Blowfish, as used on OpenBSD */
//#define CIPHER_BLOWFISH

/* Kerberos AFS DES */
//#define CIPHER_KERBEROS_AFS

/* Old style LanMan */
//#define CIPHER_LANMAN

/* Apache MD5 */
//#define CIPHER_MD5_APACHE

/* MySQL Passwords */
//#define CIPHER_MYSQL

/* Netscape LDAP */
//#define CIPHER_NETSCAPE_LDAP

/* New style windows passwords */
//#define CIPHER_NTLM

/* Lotus notes */
//#define CIPHER_LOTUS

/* Windows domain login cache files */
//#define CIPHER_MSCACHE

/* RAW MD5, as used by lots of sloppily coded webapps */
//#define CIPHER_RAWMD5

/* Eggdrop Blowfish */
//#define CIPHER_EGGDROP

/* SHA1 */
//#define CIPHER_SHA1

/* Microsoft SQL */
//#define CIPHER_MSSQL

/* HMAC MD5 */
//#define CIPHER_HMACMD5

/* WPA (wireless encryption) */
#define CIPHER_WPAPSK

/* LDAP SSL */
//#define CIPHER_NSLDAPS

/* Oracle passwords */
/* this doesnt benchmark properly, but does work when cracking */
//#define CIPHER_ORACLE

/* IPB2 cipher */
//#define CIPHER_IPB2
