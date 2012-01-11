#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

#include <ccn/ccn.h>
#include <ccn/uri.h>
#include <ccn/face_mgmt.h>
#include <ccn/reg_mgmt.h>
#include <ccn/charbuf.h>


#define CCN_DHCP_URI "ccnx:/local/dhcp"
#define CCN_DHCP_CONFIG "ccn_dhcp_server.conf"
#define CCN_DHCP_CONFIG_CLIENT "ccn_dhcp_client.conf"  
#define CCN_DHCP_ADDR "224.0.23.170"
#define CCN_DHCP_PORT "59695"
//#define CCN_DHCP_LIFETIME ((~0U) >> 1) don't use this... bad
#define CCN_DHCP_LIFETIME (1)
#define CCN_DHCP_MCASTTTL (-1)


struct ccn_dhcp_entry {
    struct ccn_charbuf *name_prefix;
    const char address[20];
    const char port[10];
    struct ccn_charbuf *store;
    struct ccn_dhcp_entry *next;
};

int join_dhcp_group(struct ccn *h);

int add_new_face(struct ccn *h, struct ccn_charbuf *prefix, const char *address, const char *port);

int ccn_dhcp_content_parse(const unsigned char *p, size_t size, struct ccn_dhcp_entry *tail);

void ccn_dhcp_content_destroy(struct ccn_dhcp_entry *head);

int ccnb_append_dhcp_content(struct ccn_charbuf *c, int count, const struct ccn_dhcp_entry *head);

