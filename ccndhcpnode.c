/**
 * @file ccndhcpnode.c
 * Start DHCP nodes on all computers (with the server flag for the "server")
 * Copyright (C) 2011 Cheng Yi <yic@email.arizona.edu>, 
 *                  Greg Lutostanski <lutostag@email.arizona.edu>
 *
 * This work is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License version 2 as published by the
 * Free Software Foundation.
 * This work is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details. You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */
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
#define CCN_DHCP_CONTENT_URI "ccnx:/local/dhcp/content"
#define CCN_DHCP_CONFIG "ccn_dhcp_server.conf"
#define CCN_DHCP_CONFIT_CLIENT "ccn_dhcp_client.conf"  
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

void ccndhcp_warn(int lineno, const char *format, ...)
{
    struct timeval t;
    va_list ap;
    va_start(ap, format);
    gettimeofday(&t, NULL);
    fprintf(stderr, "%d.%06d ccndhcp[%d]:%d: ", (int)t.tv_sec, (unsigned)t.tv_usec, (int)getpid(), lineno);
    vfprintf(stderr, format, ap);
    va_end(ap);
}

void ccndhcp_fatal(int lineno, const char *format, ...)
{
    struct timeval t;
    va_list ap;
    va_start(ap, format);
    gettimeofday(&t, NULL);
    fprintf(stderr, "%d.%06d ccndhcp[%d]:%d: ", (int)t.tv_sec, (unsigned)t.tv_usec, (int)getpid(), lineno);
    vfprintf(stderr, format, ap);
    va_end(ap);
    exit(1);
}

#define ON_ERROR_EXIT(resval, msg) on_error_exit((resval), __LINE__, msg)

static void on_error_exit(int res, int lineno, const char *msg)
{
    if (res >= 0)
        return;
    ccndhcp_fatal(lineno, "fatal error, res = %d, %s\n", res, msg);
}

#define ON_ERROR_CLEANUP(resval) \
{           \
    if ((resval) < 0) { \
        ccndhcp_warn (__LINE__, "OnError cleanup\n"); \
        goto cleanup; \
    } \
}

#define ON_NULL_CLEANUP(resval) \
{           \
    if ((resval) == NULL) { \
        ccndhcp_warn(__LINE__, "OnNull cleanup\n"); \
        goto cleanup; \
    } \
}

/*
 * Bind a prefix to a face
 */
int register_prefix(struct ccn *h, struct ccn_charbuf *local_scope_template,
        struct ccn_charbuf *no_name, struct ccn_charbuf *name_prefix,
        struct ccn_face_instance *face_instance)
{
    struct ccn_charbuf *temp = NULL;
    struct ccn_charbuf *resultbuf = NULL;
    struct ccn_charbuf *signed_info = NULL;
    struct ccn_charbuf *name = NULL;
    struct ccn_charbuf *prefixreg = NULL;
    struct ccn_parsed_ContentObject pcobuf = {0};
    struct ccn_forwarding_entry forwarding_entry_storage = {0};
    struct ccn_forwarding_entry *forwarding_entry = &forwarding_entry_storage;
    struct ccn_forwarding_entry *new_forwarding_entry;
    const unsigned char *ptr = NULL;
    size_t length = 0;
    int res;

    /* Register or unregister the prefix */
    forwarding_entry->action = "prefixreg";
    forwarding_entry->name_prefix = name_prefix;
    forwarding_entry->ccnd_id = face_instance->ccnd_id;
    forwarding_entry->ccnd_id_size = face_instance->ccnd_id_size;
    forwarding_entry->faceid = face_instance->faceid;
    forwarding_entry->flags = -1;
    forwarding_entry->lifetime = (~0U) >> 1;

    prefixreg = ccn_charbuf_create();
    ccnb_append_forwarding_entry(prefixreg, forwarding_entry);
    temp = ccn_charbuf_create();
    res = ccn_sign_content(h, temp, no_name, NULL, prefixreg->buf, prefixreg->length);
    resultbuf = ccn_charbuf_create();

    /* construct Interest containing prefixreg request */
    name = ccn_charbuf_create();
    ccn_name_init(name);
    ccn_name_append_str(name, "ccnx");
    ccn_name_append(name, face_instance->ccnd_id, face_instance->ccnd_id_size);
    ccn_name_append_str(name, "prefixreg");
    ccn_name_append(name, temp->buf, temp->length);

    /* send Interest, get Data */
    res = ccn_get(h, name, local_scope_template, 1000, resultbuf, &pcobuf, NULL, 0);
    ON_ERROR_CLEANUP(res);

    res = ccn_content_get_value(resultbuf->buf, resultbuf->length, &pcobuf, &ptr, &length);
    ON_ERROR_CLEANUP(res);
    /* extract new forwarding entry from Data */
    new_forwarding_entry = ccn_forwarding_entry_parse(ptr, length);
    ON_NULL_CLEANUP(new_forwarding_entry);

    res = new_forwarding_entry->faceid;

    ccn_forwarding_entry_destroy(&new_forwarding_entry);
    ccn_charbuf_destroy(&signed_info);
    ccn_charbuf_destroy(&temp);
    ccn_charbuf_destroy(&resultbuf);
    ccn_charbuf_destroy(&name);
    ccn_charbuf_destroy(&prefixreg);

    return res;

cleanup:
    ccn_forwarding_entry_destroy(&new_forwarding_entry);
    ccn_charbuf_destroy(&signed_info);
    ccn_charbuf_destroy(&temp);
    ccn_charbuf_destroy(&resultbuf);
    ccn_charbuf_destroy(&name);
    ccn_charbuf_destroy(&prefixreg);

    return -1;
}

/*
 * Create new face by sending out a request Interest
 * The actual new face instance is returned
 */
struct ccn_face_instance *create_face(struct ccn *h, struct ccn_charbuf *local_scope_template,
        struct ccn_charbuf *no_name, struct ccn_face_instance *face_instance)
{
    struct ccn_charbuf *newface = NULL;
    struct ccn_charbuf *signed_info = NULL;
    struct ccn_charbuf *temp = NULL;
    struct ccn_charbuf *name = NULL;
    struct ccn_charbuf *resultbuf = NULL;
    struct ccn_parsed_ContentObject pcobuf = {0};
    struct ccn_face_instance *new_face_instance = NULL;
    const unsigned char *ptr = NULL;
    size_t length = 0;
    int res = 0;

    /* Encode the given face instance */
    newface = ccn_charbuf_create();
    ccnb_append_face_instance(newface, face_instance);

    temp = ccn_charbuf_create();
    res = ccn_sign_content(h, temp, no_name, NULL, newface->buf, newface->length);
    resultbuf = ccn_charbuf_create();

    /* Construct the Interest name that will create the face */
    name = ccn_charbuf_create();
    ccn_name_init(name);
    ccn_name_append_str(name, "ccnx");
    ccn_name_append(name, face_instance->ccnd_id, face_instance->ccnd_id_size);
    ccn_name_append_str(name, face_instance->action);
    ccn_name_append(name, temp->buf, temp->length);
    /* send Interest to retrieve Data that contains the newly created face */
    res = ccn_get(h, name, local_scope_template, 1000, resultbuf, &pcobuf, NULL, 0);
    ON_ERROR_CLEANUP(res);

    /* decode Data to get the actual face instance */
    res = ccn_content_get_value(resultbuf->buf, resultbuf->length, &pcobuf, &ptr, &length);
    ON_ERROR_CLEANUP(res);

    new_face_instance = ccn_face_instance_parse(ptr, length);

    ccn_charbuf_destroy(&newface);
    ccn_charbuf_destroy(&signed_info);
    ccn_charbuf_destroy(&temp);
    ccn_charbuf_destroy(&resultbuf);
    ccn_charbuf_destroy(&name);

    return new_face_instance;

cleanup:
    ccn_charbuf_destroy(&newface);
    ccn_charbuf_destroy(&signed_info);
    ccn_charbuf_destroy(&temp);
    ccn_charbuf_destroy(&resultbuf);
    ccn_charbuf_destroy(&name);

    return NULL;
}

/*
 * Get ccnd id
 */
static int get_ccndid(struct ccn *h, struct ccn_charbuf *local_scope_template,
        const unsigned char *ccndid)
{
    struct ccn_charbuf *name = NULL;
    struct ccn_charbuf *resultbuf = NULL;
    struct ccn_parsed_ContentObject pcobuf = {0};
    char ccndid_uri[] = "ccnx:/%C1.M.S.localhost/%C1.M.SRV/ccnd/KEY";
    const unsigned char *ccndid_result;
    static size_t ccndid_result_size;
    int res;

    name = ccn_charbuf_create();
    resultbuf = ccn_charbuf_create();

    res = ccn_name_from_uri(name, ccndid_uri);
    ON_ERROR_EXIT(res, "Unable to parse service locator URI for ccnd key\n");

    /* get Data */
    res = ccn_get(h, name, local_scope_template, 4500, resultbuf, &pcobuf, NULL, 0);
    ON_ERROR_EXIT(res, "Unable to get key from ccnd\n");

    /* extract from Data */
    res = ccn_ref_tagged_BLOB(CCN_DTAG_PublisherPublicKeyDigest,
            resultbuf->buf,
            pcobuf.offset[CCN_PCO_B_PublisherPublicKeyDigest],
            pcobuf.offset[CCN_PCO_E_PublisherPublicKeyDigest],
            &ccndid_result, &ccndid_result_size);
    ON_ERROR_EXIT(res, "Unable to parse ccnd response for ccnd id\n");

    memcpy((void *)ccndid, ccndid_result, ccndid_result_size);

    ccn_charbuf_destroy(&name);
    ccn_charbuf_destroy(&resultbuf);

    return (ccndid_result_size);
}

/*
 * Construct a new face instance based on the given address and port
 * This face instance is only used to send new face request
 */
struct ccn_face_instance *construct_face(const unsigned char *ccndid, size_t ccndid_size,
        const char *address, const char *port)
{
    struct ccn_face_instance *fi = calloc(1, sizeof(*fi));
    char rhostnamebuf[NI_MAXHOST];
    char rhostportbuf[NI_MAXSERV];
    struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_flags = (AI_ADDRCONFIG),
        .ai_socktype = SOCK_DGRAM};
    struct addrinfo *raddrinfo = NULL;
    struct ccn_charbuf *store = ccn_charbuf_create();
    int host_off = -1;
    int port_off = -1;
    int res;

    res = getaddrinfo(address, port, &hints, &raddrinfo);
    if (res != 0 || raddrinfo == NULL) {
        fprintf(stderr, "Error: getaddrinfo, make sure supplied address and port are valid; %s:%s\n", address, port);
        exit(1);
    }

    res = getnameinfo(raddrinfo->ai_addr, raddrinfo->ai_addrlen,
            rhostnamebuf, sizeof(rhostnamebuf),
            rhostportbuf, sizeof(rhostportbuf),
            NI_NUMERICHOST | NI_NUMERICSERV);
    freeaddrinfo(raddrinfo);
    if (res != 0) {
        fprintf(stderr, "Error: getnameinfo, make sure supplied address and port are valid; %s:%s\n", address, port);
        exit(1);
    }

    fi->store = store;
    fi->descr.ipproto = IPPROTO_UDP;
    fi->descr.mcast_ttl = CCN_DHCP_MCASTTTL;
    fi->lifetime = CCN_DHCP_LIFETIME;

    ccn_charbuf_append(store, "newface", strlen("newface") + 1);
    host_off = store->length;
    ccn_charbuf_append(store, rhostnamebuf, strlen(rhostnamebuf) + 1);
    port_off = store->length;
    ccn_charbuf_append(store, rhostportbuf, strlen(rhostportbuf) + 1);

    char *b = (char *)store->buf;
    fi->action = b;
    fi->descr.address = b + host_off;
    fi->descr.port = b + port_off;
    fi->descr.source_address = NULL;
    fi->ccnd_id = ccndid;
    fi->ccnd_id_size = ccndid_size;

    return fi;
}

/*
 * initialize local data
 */
void init_data(struct ccn_charbuf *local_scope_template,
        struct ccn_charbuf *no_name)
{
    ccn_charbuf_append_tt(local_scope_template, CCN_DTAG_Interest, CCN_DTAG);
    ccn_charbuf_append_tt(local_scope_template, CCN_DTAG_Name, CCN_DTAG);
    ccn_charbuf_append_closer(local_scope_template);    /* </Name> */
    ccnb_tagged_putf(local_scope_template, CCN_DTAG_Scope, "1");
    ccn_charbuf_append_closer(local_scope_template);    /* </Interest> */

    ccn_name_init(no_name);
}

/*
 * Create a newface on the given address and port, bind the prefix to the face
 */
int add_new_face(struct ccn *h, struct ccn_charbuf *prefix, const char *address, const char *port)
{
    struct ccn_charbuf *local_scope_template = ccn_charbuf_create();
    struct ccn_charbuf *no_name = ccn_charbuf_create();
    unsigned char ccndid_storage[32] = {0};
    const unsigned char *ccndid = ccndid_storage;
    size_t ccndid_size = 0;
    struct ccn_face_instance *fi;
    struct ccn_face_instance *nfi;
    int res;

    init_data(local_scope_template, no_name);

    ccndid_size = get_ccndid(h, local_scope_template, ccndid);
    if (ccndid_size != sizeof(ccndid_storage))
    {
        fprintf(stderr, "Incorrect size for ccnd id in response\n");
        ON_ERROR_CLEANUP(-1);
    }

    /* construct a face instance for new face request */
    fi = construct_face(ccndid, ccndid_size, address, port);
    ON_NULL_CLEANUP(fi);

    /* send new face request to actually create a new face */
    nfi = create_face(h, local_scope_template, no_name, fi);
    ON_NULL_CLEANUP(nfi);

    /* bind prefix to the new face */
    res = register_prefix(h, local_scope_template, no_name, prefix, nfi);
    ON_ERROR_CLEANUP(res);

    ccn_charbuf_destroy(&local_scope_template);
    ccn_charbuf_destroy(&no_name);
    ccn_face_instance_destroy(&fi);
    ccn_face_instance_destroy(&nfi);

    return 0;

cleanup:
    ccn_charbuf_destroy(&local_scope_template);
    ccn_charbuf_destroy(&no_name);
    ccn_face_instance_destroy(&fi);
    ccn_face_instance_destroy(&nfi);

    return -1;
}

/*
 * Create a face on the multicast address and port, bind the DHCP prefix to the face
 */
int join_dhcp_group(struct ccn *h)
{
    int res;
    struct ccn_charbuf *prefix = ccn_charbuf_create();

    ccn_name_from_uri(prefix, CCN_DHCP_URI);
    res = add_new_face(h, prefix, CCN_DHCP_ADDR, CCN_DHCP_PORT);

    ccn_charbuf_destroy(&prefix);

    return res;
}

void ccn_dhcp_entry_destroy(struct ccn_dhcp_entry **de)
{
    if (*de != NULL) {
        ccn_charbuf_destroy(&(*de)->name_prefix);
        ccn_charbuf_destroy(&(*de)->store);
        free(*de);
        *de = NULL;
    }
}

void ccn_dhcp_content_destroy(struct ccn_dhcp_entry *head)
{
    struct ccn_dhcp_entry *de = head;
    struct ccn_dhcp_entry *next;

    while (de != NULL) {
        next = de->next;
        ccn_dhcp_entry_destroy(&de);
        de = next;
    }
}

int ccn_dhcp_content_parse(const unsigned char *p, size_t size, struct ccn_dhcp_entry *tail)
{
    struct ccn_buf_decoder decoder;
    struct ccn_buf_decoder *d = ccn_buf_decoder_start(&decoder, p, size);
    int i;
    int count;
    struct ccn_dhcp_entry *de = tail;

    if (ccn_buf_match_dtag(d, CCN_DTAG_Entry)) {
        ccn_buf_advance(d);

        count = ccn_parse_optional_tagged_nonNegativeInteger(d, CCN_DTAG_Count);

        for (i = 0; i < count; i ++) {
            struct ccn_charbuf *store = ccn_charbuf_create();
            size_t start;
            size_t end;
            int host_off = -1;
            int port_off = -1;

            de->next = calloc(1, sizeof(*de));
            de = de->next;
            memset(de, 0, sizeof(*de));
            de->store = store;
            de->next = NULL;

            if (ccn_buf_match_dtag(d, CCN_DTAG_Name)) {
                de->name_prefix = ccn_charbuf_create();
                start = d->decoder.token_index;
                ccn_parse_Name(d, NULL);
                end = d->decoder.token_index;
                ccn_charbuf_append(de->name_prefix, p + start, end - start);
            }
            else
                de->name_prefix = NULL;

            host_off = ccn_parse_tagged_string(d, CCN_DTAG_Host, store);
            port_off = ccn_parse_tagged_string(d, CCN_DTAG_Port, store);

            char *b = (char *)store->buf;
            char *h = b + host_off;
            char *p = b + port_off;
            if (host_off >= 0)
                memcpy((void *)de->address, h, strlen(h));
            if (port_off >= 0)
                memcpy((void *)de->port, p, strlen(p));
        }
    }
    else
        d->decoder.state = -__LINE__;

    if (d->decoder.index != size || !CCN_FINAL_DSTATE(d->decoder.state))
        ccn_dhcp_content_destroy(tail->next);

    return count;
}

int ccnb_append_dhcp_content(struct ccn_charbuf *c, int count, const struct ccn_dhcp_entry *head)
{
    int res;
    int i;
    const struct ccn_dhcp_entry *de = head;

    res = ccnb_element_begin(c, CCN_DTAG_Entry);
    res |= ccnb_tagged_putf(c, CCN_DTAG_Count, "%d", count);

    for (i = 0; i < count; i ++) {
        if (de == NULL)
        {
            fprintf(stderr, "Error: number of ccn_dhcp_entry does not match\n");
            break;
        }

        if (de->name_prefix != NULL && de->name_prefix->length > 0)
            res |= ccn_charbuf_append(c, de->name_prefix->buf, de->name_prefix->length);

        if (de->address != NULL)
            res |= ccnb_tagged_putf(c, CCN_DTAG_Host, "%s", de->address);
        if (de->port != NULL)
            res |= ccnb_tagged_putf(c, CCN_DTAG_Port, "%s", de->port);

        de = de->next;
    }

    res |= ccnb_element_end(c);
    return res;
}


struct mydata {
    int debug_flag;
    int is_server;
    int freshness_seconds;
    int num_entries;
    struct ccn_dhcp_entry *entries;
};

static void usage(const char *progname)
{
    fprintf(stderr,
            "%s [-hdus] [-t freshness_seconds] [-f config_file]\n"
            "\n"
            "\t-h displays this help information\n"
            "\t-d logs some info to stdout\n"
            "\t-u flag to allow the server to add the entries from the config file (default is not)\n"
            "\t-s signifies that this is node starts as a server\n"
            "\t-t sets the stale timeout of the dhcp records ContentObjects (default: 60)\n"
            "\t-f change the defalut config file name"
            "\t./ccn_dhcp.config is read by default if no config file is specified and the node starts as a server\n"
            , progname);
    exit(1);
}

int read_config_file(const char *filename, struct ccn_dhcp_entry *tail, int normal)
{
    char *uri;
    char *host;
    char *port;
    FILE *cfg;
    char buf[1024];
    int len;
    char *cp;
    char *last = NULL;
    const char *seps = " \t\n";
    struct ccn_dhcp_entry *de = tail;
    int count = 0;
    int res = 0;

    cfg = fopen(filename, "r");
    if (cfg == NULL) {
        fprintf(stderr, "Error opening file %s: %s\n", filename, strerror(errno));
        exit(1);
    }

    while (fgets((char *)buf, sizeof(buf), cfg)) {
        len = strlen(buf);
        if (buf[0] == '#' || len == 0)
            continue;

        if (normal == 1 && buf[0] == '!')
            continue;

        if (normal != 1 && buf[0] != '!')
            continue;

        if (buf[0] == '!')
            buf[0] = ' ';

        if (buf[len - 1] == '\n')
            buf[len - 1] = '\0';

        cp = index(buf, '#');
        if (cp != NULL)
            *cp = '\0';

        uri = strtok_r(buf, seps, &last);
        if (uri == NULL)    /* blank line */
            continue;

        de->next = calloc(1, sizeof(*de));
        de = de->next;
        memset(de, 0, sizeof(*de));
        de->next = NULL;
        de->store = NULL;

        host = strtok_r(NULL, seps, &last);
        port = strtok_r(NULL, seps, &last);

        de->name_prefix = ccn_charbuf_create();
        res = ccn_name_from_uri(de->name_prefix, uri);
        if (res < 0) {
            fprintf(stderr, "Bad URI format: %s\n", uri);
            exit(1);
        }

        memcpy((void *)de->address, host, strlen(host));
        memcpy((void *)de->port, port, strlen(port));

        count ++;
    }

    fclose(cfg);

    return count;
}

/* Publish DHCP content */
int put_dhcp_content(struct ccn *h, int fresh_seconds, int entry_count, struct ccn_dhcp_entry *de)
{
    struct ccn_charbuf *name = ccn_charbuf_create();
    struct ccn_charbuf *resultbuf = ccn_charbuf_create();
    struct ccn_signing_params sp = CCN_SIGNING_PARAMS_INIT;
    struct ccn_charbuf *body = ccn_charbuf_create();
    int res;

    ccn_name_from_uri(name, CCN_DHCP_CONTENT_URI);
    sp.type = CCN_CONTENT_DATA;
    sp.freshness = fresh_seconds;


    res = ccnb_append_dhcp_content(body, entry_count, de->next);
    if (res < 0) {
        fprintf(stderr, "Error appending DHCP content.\n");
        goto cleanup;
    }

    res = ccn_sign_content(h, resultbuf, name, &sp, body->buf, body->length);
    if (res < 0) {
        fprintf(stderr, "Failed to encode ContentObject.\n");
        goto cleanup;
    }

    res = ccn_put(h, resultbuf->buf, resultbuf->length);
    if (res < 0) {
        fprintf(stderr, "ccn_put failed.\n");
        goto cleanup;
    }

    ccn_charbuf_destroy(&body);
    ccn_charbuf_destroy(&name);
    ccn_charbuf_destroy(&resultbuf);

    return 0;
cleanup:
    ccn_charbuf_destroy(&body);
    ccn_charbuf_destroy(&name);
    ccn_charbuf_destroy(&resultbuf);
    ccn_dhcp_content_destroy(de->next);

    return -1;
}

/* Receive dhcp content */
int get_dhcp_content(struct ccn *h, struct ccn_dhcp_entry *tail, int msecs)
{
    struct ccn_charbuf *name = ccn_charbuf_create();
    struct ccn_charbuf *resultbuf = ccn_charbuf_create();
    struct ccn_parsed_ContentObject pcobuf = {0};
    int res;
    const unsigned char *ptr;
    size_t length;
    int count = 0;

    ccn_name_from_uri(name, CCN_DHCP_CONTENT_URI);

    res = ccn_get(h, name, NULL, msecs, resultbuf, &pcobuf, NULL, 0);
    if (res < 0) {
        fprintf(stderr, "Error getting DHCP content\n");
        ccn_charbuf_destroy(&name);
        ccn_charbuf_destroy(&resultbuf);
        return -1;
    }

    ptr = resultbuf->buf;
    length = resultbuf->length;
    ccn_content_get_value(ptr, length, &pcobuf, &ptr, &length);
    count = ccn_dhcp_content_parse(ptr, length, tail);

    ccn_charbuf_destroy(&name);
    ccn_charbuf_destroy(&resultbuf);

    return count;
}




int compare_bufs(unsigned char *one, int l1, unsigned char *two, int l2){
    int x;
    if(l1 != l2){
        return -1;
    }
    for(x = 0; x< l1; x++){
        if(one[x] != two[x])
            return -1;
    }
    return 0;
}
//repeated to supress useless warnings
int compare_chars(const char *one, int l1, const char *two, int l2){
    int x;
    if(l1 != l2){
        return -1;
    }
    for(x = 0; x< l1; x++){
        if(one[x] != two[x])
            return -1;
    }
    return 0;
}

int compare_entries(struct ccn_dhcp_entry *one, struct ccn_dhcp_entry *two){
    if((compare_bufs(one->name_prefix->buf, one->name_prefix->length, two->name_prefix->buf, two->name_prefix->length) == 0) &&
        (compare_chars(one->address, 20, two->address, 20) == 0) &&
        (compare_chars(one->port, 10, two->port, 10) == 0))
        return 0;
    return -1;

}

int update_faces(struct ccn *h, struct mydata *mydata, struct ccn_dhcp_entry *new_entries, int num_new, int add_faces){
    struct ccn_dhcp_entry *current_new = new_entries;
    struct ccn_dhcp_entry *current_old;
    int test = 0;
    int x, y;
    
    for(x=0; x < num_new; x++){
        current_new = current_new->next;
        current_old = mydata->entries;
        for(y=0; y < mydata->num_entries; y++){
            current_old = current_old->next;
            if(compare_entries(current_new, current_old) == 0){
                test = 1;
                break;
            }
        }
        if(test == 0){
            //now we are going to update the entries we know about
            current_old->next = calloc(1, sizeof(*current_new));
            memcpy(current_old->next, current_new, sizeof(*current_new));
            mydata->num_entries++;
            
            //we need to add this face because we have not seen it yet
            if(add_faces == 1)
                add_new_face(h, current_new->name_prefix, current_new->address, current_new->port);
        }
    }

    return 1;

}

/* We received a response to one of our interests -- not used yet nor tested*/
enum ccn_upcall_res
incoming_content(
    struct ccn_closure *selfp,
    enum ccn_upcall_kind kind,
    struct ccn_upcall_info *info)
{
    struct mydata *md = selfp->data;
    const unsigned char *ccnb = NULL;
    size_t ccnb_size = 0;
    const unsigned char *data = NULL;
    size_t data_size = 0;
    int res;
    int count = 0;
    struct ccn_dhcp_entry new_val = {0};
    struct ccn_dhcp_entry *tail = &new_val;

    if (kind == CCN_UPCALL_FINAL)
        return(CCN_UPCALL_RESULT_OK);
    if (kind == CCN_UPCALL_INTEREST_TIMED_OUT)
        return(CCN_UPCALL_RESULT_OK);
    if ((kind != CCN_UPCALL_CONTENT && kind != CCN_UPCALL_CONTENT_UNVERIFIED) || md == NULL)
        return(CCN_UPCALL_RESULT_ERR);

    ccnb = info->content_ccnb;
    ccnb_size = info->pco->offset[CCN_PCO_E];
    res = ccn_content_get_value(ccnb, ccnb_size, info->pco, &data, &data_size);
    if (res < 0) {
        fprintf(stderr, "Error processing incoming ContentObject\n");
        exit(1);
    }

    count = ccn_dhcp_content_parse(data, data_size, tail);

    update_faces(info->h, selfp->data, tail, count, 1);

//    ccn_set_run_timeout(info->h, 0);
    return(CCN_UPCALL_RESULT_OK);
}

void print_entries(struct mydata *mydata){
    if(mydata->debug_flag == 1){
        struct ccn_dhcp_entry *current_new = mydata->entries;
        int x;
        printf("We are printing entries now (%d):\n", mydata->num_entries);
        for(x=0; x < mydata->num_entries; x++){
            current_new = current_new->next;
            printf("\t%d: %s\n",x , ccn_charbuf_as_string(current_new->name_prefix));
        }
    }
}

/* Someone asked for our dhcp entries, so we will respond with them -- only if we are a server*/
enum ccn_upcall_res
incoming_interest(
    struct ccn_closure *selfp,
    enum ccn_upcall_kind kind,
    struct ccn_upcall_info *info)
{
    int res;
    struct mydata *md = selfp->data;

    //if we are not a server hopefully they will get a response from our non-stale data
    if(md->is_server != 1)
        return(CCN_UPCALL_RESULT_OK);

    if(md->debug_flag == 1)
        printf("incoming interest\n");
    if (kind == CCN_UPCALL_FINAL)
        return(CCN_UPCALL_RESULT_OK);
    if (kind == CCN_UPCALL_CONSUMED_INTEREST)
        return(CCN_UPCALL_RESULT_OK);
    if (kind != CCN_UPCALL_INTEREST || md == NULL || md->num_entries == 0)
        return(CCN_UPCALL_RESULT_ERR);

    
    print_entries(md);
    if(md->debug_flag == 1)
        printf("putting content, this many entries: %d\n", md->num_entries);
    
    res = put_dhcp_content(info->h, md->freshness_seconds, md->num_entries, md->entries);

    if (res < 0)
        ccn_perror(info->h, "Cannot publish DHCP content.");

    ccn_set_run_timeout(info->h, 0);
    return(CCN_UPCALL_RESULT_INTEREST_CONSUMED);
}

/* TODO: change the following to work for doing periodic updates from sched */
//static int
//periodic_update(struct ccn_schedule *sched, void *clienth, 
//         struct ccn_scheduled_event *ev, int flags)
//{
//    struct timeval now = {0};
//    struct mydata *md = clienth;
//    gettimeofday(&now, 0);
//    if ((flags & CCN_SCHEDULE_CANCEL) != 0) {
//        md->report = NULL;
//        return(0);
//    }
//    return(3000000);
//}

int main(int argc, char **argv)
{
    struct ccn *h = NULL;
    const char *config_file = CCN_DHCP_CONFIG_CLIENT;
    struct ccn_charbuf *name = ccn_charbuf_create();
    int server_add_faces = 0;
    int entry_count = 0;
    int fresh_secs = 60; //set it to 1 min, max is 2146 secs
    int res;
    int set_config_file = 0;
    struct mydata *mydata;
    struct ccn_dhcp_entry new_val = {0};
    struct ccn_dhcp_entry *new = &new_val;
    struct ccn_closure *in_content;
    struct ccn_closure *in_interest;
    //Variables that hold the dhcp table state
    struct ccn_dhcp_entry *de_storage;
    de_storage = calloc(1, sizeof(*de_storage));
    mydata = calloc(1, sizeof(*mydata));
    mydata->entries = de_storage;
    mydata->num_entries = 0;
    mydata->debug_flag = 0;
    mydata->is_server = 0;

    //process args
    while ((res = getopt(argc, argv, "f:t:dush")) != -1) {
        switch (res) {
            case 'f':
                set_config_file = 1;
                config_file = optarg;
                break;
            case 't':
                fresh_secs = atoi(optarg);
                break;
            case 'd':
                mydata->debug_flag = 1;
                break;
            case 's':
                if(set_config_file == 0)
                    config_file = CCN_DHCP_CONFIG;
                mydata->is_server = 1;
                break;
            case 'u':
                server_add_faces = 1;
                break;
            case 'h':
            default:
                usage(argv[0]);
        }
    }

    //change the freshness_seconds
    mydata->freshness_seconds = fresh_secs;

    in_content = calloc(1, sizeof(*in_content));
    in_content->p = &incoming_content;
    in_content->data = mydata;
    in_interest = calloc(1, sizeof(*in_interest));
    in_interest->p = &incoming_interest;
    in_interest->data = mydata;
    
    //setup connection to the ccndaemon and multicast group
    h = ccn_create();
    res = ccn_connect(h, NULL);
    if (res < 0) {
        ccn_perror(h, "Cannot connect to ccnd.");
        exit(1);
    }

    res = join_dhcp_group(h);
    if (res < 0) {
        ccn_perror(h, "Cannot join DHCP group.");
        exit(1);
    }

    //get first entries -- either by asking or reading config file
    //only setup faces for the clients unless you set the cmdline flag
    if (mydata->is_server == 1){
        entry_count = read_config_file(config_file, new, 1);
        if(server_add_faces)
            update_faces(h, mydata, new, entry_count, 1);
        else
            update_faces(h, mydata, new, entry_count, 0);
    }
    else{
        //default is to wait for a response for 8 seconds
        entry_count = get_dhcp_content(h, new, 8000);
        if(entry_count == -1){
            //There was an error getting the content so we are going to fallback
            entry_count = read_config_file(config_file, new, 0);
        }
        update_faces(h, mydata, new, entry_count, 1);
        print_entries(mydata);
        ccn_destroy(&h);
        exit(0);
    }

    print_entries(mydata);
    //now we setup a callback function that will respond to further queries
    ccn_name_from_uri(name, CCN_DHCP_CONTENT_URI);
    ccn_set_interest_filter(h, name, in_interest);


    //we will schedule a periodic update that will look for the newest dhcp information
    //and do leases for the appropriate length of time
    //XXX:TODO
    
    //main loooooooo...oooooop
    while(1){
        ccn_run(h, -1);
    }

    ccn_destroy(&h);
    exit(0);
}
