typedef struct header {
    char *name;
    char *value;
    struct header *next;
} header;

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

response *http_request(const char *host, const char *path);
response *http_request_url(const char *url);

int http_read_body(response *response);

const char *http_header(response *response, const char *name);

void free_response(response *response);
