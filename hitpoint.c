#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>

#include "hitpoint.h"
#include "http-parser/http_parser.h"
#include "sds/sds.h"

static int http_connect(const char *host, int port)
{
    int fd;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    
    if ((server = gethostbyname(host)) == NULL) {
        fprintf(stderr, "no such host %s\n", host);
        return -1;
    }
    
    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "could not open socket");
        return -1;
    }

    bzero((char *) &serv_addr, sizeof(serv_addr));
    bcopy((char *)server->h_addr, 
         (char *)&serv_addr.sin_addr.s_addr,
         server->h_length);
    serv_addr.sin_port = htons(port);

    if (connect(fd, (const struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)  {
        fprintf(stderr, "could not connect to %s\n", host);
        return -1;
    }

    return fd;
}

const char *http_header(response *response, const char *name)
{
    header *header = response->headers;

    while (header != NULL) {
        if (strcasecmp(header->name, name) == 0) {
            return header->value;
        }
        header = header->next;
    }

    return NULL;
}

void http_add_header(request *request, const char *name, const char *value)
{
    header *header = malloc(sizeof(struct header));
    header->name = sdsnew(name);
    header->value = sdsnew(value);
    header->next = request->headers;
    request->headers = header;
}

int http_request_url(request *request, const char *url)
{
    struct http_parser_url parser_url;

    if (http_parser_parse_url(url, strlen(url), 0, &parser_url) != 0) {
        fprintf(stderr, "invalid url: %s\n", url);
        return -1;
    }

    request->host = sdsnewlen(url + parser_url.field_data[UF_HOST].off, parser_url.field_data[UF_HOST].len);
    request->port = 80;
    request->path = sdscatsds(sdscat(sdsnewlen(url + parser_url.field_data[UF_PATH].off, parser_url.field_data[UF_PATH].len), "?"),
                             sdsnewlen(url + parser_url.field_data[UF_QUERY].off, parser_url.field_data[UF_QUERY].len));

    return 0;
}

request *http_new_request(int method)
{
    request *request = malloc(sizeof(struct request));
    memset(request, 0, sizeof(struct request));
    request->method = method;
    return request;
}

request *http_get(const char *url)
{
    request *request = http_new_request(HTTP_GET);
    http_request_url(request, url);
    return request;
}

request *http_post(const char *url, const char *body)
{
    request *request = http_new_request(HTTP_POST);
    request->body = body;
    http_request_url(request, url);
    return request;
}

int on_url(http_parser *parser, const char *at, size_t len) {
    return 0;
}
    
int on_message_begin(http_parser *parser) {
    return 0;
}

static int on_header_field(http_parser *parser, const char *at, size_t len) {
    response *response = parser->data;
    header *header;

    if (response->header_state != 1) {
        header = malloc(sizeof(struct header));
        header->name = NULL;
        header->value = NULL;
        header->next = response->headers;
        response->headers = header;
    } else {
        header = response->headers;
    }

    sds s = sdsnewlen(at, len);
    header->name = header->name == NULL ? s : sdscatsds(header->name, s);
    response->header_state = 1;

    return 0;
}

static int on_header_value(http_parser *parser, const char *at, size_t len) {
    response *response = parser->data;
    header *header = response->headers;

    sds s = sdsnewlen(at, len);
    header->value = header->value == NULL ? s : sdscatsds(header->value, s);
    response->header_state = 2;
    return 0;
}

int on_status(http_parser *parser, const char *at, size_t len) {
    response *response = parser->data;
    response->status = parser->status_code;
    response->content_length = parser->content_length;
    return 0;
}

int on_headers_complete(http_parser *parser) {
    response *response = parser->data;
    response->status = parser->status_code;
    response->content_length = parser->content_length;
    return 0;
}

int on_message_complete(http_parser *parser) {
    response *response = parser->data;
    response->complete = 1;
    return 0;
}

http_parser_settings parser_settings = {
    .on_message_begin = on_message_begin,
    .on_url = on_url,
    .on_status = on_status,
    .on_header_field = on_header_field,
    .on_header_value = on_header_value,
    .on_headers_complete = on_headers_complete,
    .on_message_complete = on_message_complete,
};


static int http_read_headers(http_parser *parser, response *response)
{
    int ret;
    char buf[1];
    int fd = response->fd;

    while ((ret = read(fd, buf, sizeof(buf))) > 0) {
        if (http_parser_execute(parser, &parser_settings, buf, ret) != (size_t) ret) {
            fprintf(stderr, "parse error\n");
            return -1;
        }
        if (response->status != 0) break;
    }

    return 0;
}

response *http_send(request *request)
{
    response *response = malloc(sizeof(struct response));
    memset(response, 0, sizeof(struct response));
    response->fd = http_connect(request->host, request->port);

    http_parser parser;
    http_parser_init(&parser, HTTP_RESPONSE);
    parser.data = response;

    if (response->fd < 0) {
        free_response(response);
        return NULL;
    }

    sds s = sdsempty();

    s = sdscatprintf(s, "GET %s HTTP/1.0\r\n", request->path);
    s = sdscatprintf(s, "Host: %s\r\n", request->host);

    header *header = request->headers;

    while (header != NULL) {
        s = sdscatprintf(s, "%s: %s\r\n", header->name, header->value);
        header = header->next;
    }

    sdscat(s, "\r\n");

    write(response->fd, s, sdslen(s));

    if (http_read_headers(&parser, response) != 0) {
        free_response(response);
        return NULL;
    }

    return response;
}

void free_response(response *response)
{
    header *header = response->headers;

    while (header != NULL) {
        free(header);
        sdsfree(header->name);
        sdsfree(header->value);
        header = header->next;
    }
    
    free(response->body);
    free(response);
}

        
int http_read_body(response *response)
{
    int count = 0;

    response->body = malloc(response->content_length + 1);
    memset(response->body, 0, response->content_length + 1);

    char *p = response->body;

    while ((count = read(response->fd, p, 4096)) > 0) {
        response->pos += count;
        p += count;
    }

    close(response->fd);

    return count;
}
