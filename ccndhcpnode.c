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
#include "dhcp_helper.h"

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
            "\t-d toggle logging some info to stdout\n"
            "\t-u flag to allow the server to add the entries from the config file (default is not)\n"
            "\t-s signifies that this is node starts as a server\n"
            "\t-c set the client timeout for reception of dhcp records\n"
            "\t-t sets the stale timeout of the dhcp records ContentObjects (default: 60)\n"
            "\t-f change the default config file name"
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
        if(host == NULL){
            fprintf(stderr,"Error in config file %s, look at examples!\n", filename);
            exit(-4);
        }
        port = strtok_r(NULL, seps, &last);
        if(port == NULL){
            fprintf(stderr,"Error in config file %s, look at examples!\n", filename);
            exit(-4);
        }
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

    ccn_name_from_uri(name, CCN_DHCP_URI);
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

    ccn_name_from_uri(name, CCN_DHCP_URI);

    res = ccn_get(h, name, NULL, msecs, resultbuf, &pcobuf, NULL, 0);
    if (res < 0) {
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
            (compare_chars(one->port, 10, two->port, 10) == 0)){

        return 0;
    }
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

    if (kind == CCN_UPCALL_FINAL){
        return(CCN_UPCALL_RESULT_OK);
    }
    if (kind == CCN_UPCALL_INTEREST_TIMED_OUT){
        return(CCN_UPCALL_RESULT_OK);
    }
    if ((kind != CCN_UPCALL_CONTENT && kind != CCN_UPCALL_CONTENT_UNVERIFIED) || md == NULL){
        return(CCN_UPCALL_RESULT_ERR);
    }

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
    if((mydata->debug_flag == 1 && mydata->is_server == 1)||(mydata->debug_flag == 0 && mydata->is_server == 0)){
        struct ccn_dhcp_entry *current_new = mydata->entries;
        int x;
        for(x=0; x < mydata->num_entries; x++){
            current_new = current_new->next;
            printf("\t%d: %s %s %s\n",x , ccn_charbuf_as_string(current_new->name_prefix), current_new->address, current_new->port);
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
    if(md->is_server != 1){
        return(CCN_UPCALL_RESULT_OK);
    }

    if(md->debug_flag == 1)
        printf("incoming interest\n");
    if (kind == CCN_UPCALL_FINAL){
        return(CCN_UPCALL_RESULT_OK);
    }
    if (kind == CCN_UPCALL_CONSUMED_INTEREST){
        return(CCN_UPCALL_RESULT_OK);
    }
    if (kind != CCN_UPCALL_INTEREST || md == NULL || md->num_entries == 0){
        return(CCN_UPCALL_RESULT_ERR);
    }


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
    int client_timeout = 8000;
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
    while ((res = getopt(argc, argv, "f:t:c:dush")) != -1) {
        switch (res) {
            case 'f':
                set_config_file = 1;
                config_file = optarg;
                break;
            case 't':
                fresh_secs = atoi(optarg);
                break;
            case 'c':
                client_timeout = atoi(optarg);
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
        entry_count = get_dhcp_content(h, new, client_timeout);
        if(entry_count < 1){
            //There was an error getting the content so we are going to fallback
            printf("No response, using client default entries\n");
            entry_count = read_config_file(config_file, new, 0);
        }
        update_faces(h, mydata, new, entry_count, 1);
        print_entries(mydata);
        ccn_destroy(&h);
        exit(0);
    }

    print_entries(mydata);
    //now we setup a callback function that will respond to further queries
    ccn_name_from_uri(name, CCN_DHCP_URI);
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
