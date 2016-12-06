#ifndef __ES_H__
#define __ES_H__

#include <curl_wrapper.h>

void es_init(void);
void es_close(void);
char *es_query(char *url, char *query);

#endif
