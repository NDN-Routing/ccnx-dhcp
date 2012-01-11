/**
 * @file dhcp_helper.c
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

#include "dhcp_helper.h"

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


