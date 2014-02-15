typedef struct header {
    char *name;
    char *value;
    struct header *next;
} header;

typedef struct request {
    int method;
    char *host;
    char *path;
    int port;
    header *headers;
    char *body;
} request;

typedef struct response {
    int fd;
    int status;
    int complete;
    int header_state;
    header *headers;
    char *body;
    unsigned int pos;
    unsigned int content_length;
} response;

request *http_get(char *url);

request *http_post(char *url, char *body);

response *http_send(request *request);

int http_read_body(response *response);

const char *http_header(response *response, const char *name);

void http_add_header(request *request, const char *name, const char *value);

void free_response(response *response);
