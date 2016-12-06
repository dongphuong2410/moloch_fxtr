#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "es.h"

#define LONG_STR_SIZE 10240

static void _cb(char *text, void *userdata);

static char URL[] = "127.0.0.1:9200";
static CurlWrapper_t *es_conn;
static char *es_out;

void es_init(void)
{
    es_conn = http_init(URL);
    es_out = (char *)malloc(sizeof(char) * LONG_STR_SIZE);
}

void es_close(void)
{
    http_destroy(es_conn);
    free(es_out);
}

char *es_query(char *url, char *query)
{
    http_param_set(es_conn, CURL_WRAPPER_POST, url, query, _cb);
    http_set_data(es_conn);
    http_send(es_conn, NULL);
    return es_out;
}

static void _cb(char *text, void *userdata)
{
    strcpy(es_out, text);
}
