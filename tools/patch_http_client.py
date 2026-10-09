"""Build-local fix for ESP8266 SDK v3.4's fragmented HTTP header callbacks."""
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text()
start = source.index('static int http_on_header_field(')
end = source.index('static int http_on_headers_complete(', start)
callbacks = r'''
/* SDK callbacks can receive a header field/value across multiple reads. */
static int append_header(char **text, const char *at, size_t length)
{
    size_t used = *text ? strlen(*text) : 0;
    if (length > 4096 - used) return -1;
    char *next = realloc(*text, used + length + 1);
    if (!next) return -1;
    memcpy(next + used, at, length);
    next[used + length] = 0;
    *text = next;
    return 0;
}

static void finish_header(esp_http_client_handle_t client)
{
    if (client->current_header_key && client->current_header_value) {
        const char *key = client->current_header_key;
        const char *value = client->current_header_value;
        if (!strcasecmp(key, "Location")) {
            http_utils_assign_string(&client->location, value, strlen(value));
        } else if (!strcasecmp(key, "Transfer-Encoding") && !strcasecmp(value, "chunked")) {
            client->response->is_chunked = true;
        } else if (!strcasecmp(key, "WWW-Authenticate")) {
            http_utils_assign_string(&client->auth_header, value, strlen(value));
        }
        client->event.header_key = client->current_header_key;
        client->event.header_value = client->current_header_value;
        http_dispatch_event(client, HTTP_EVENT_ON_HEADER, NULL, 0);
    }
    free(client->current_header_key);
    free(client->current_header_value);
    client->current_header_key = NULL;
    client->current_header_value = NULL;
    client->current_header_is_value = false;
}

static int http_on_header_field(http_parser *parser, const char *at, size_t length)
{
    esp_http_client_t *client = parser->data;
    if (client->current_header_is_value) finish_header(client);
    return append_header(&client->current_header_key, at, length);
}

static int http_on_header_value(http_parser *parser, const char *at, size_t length)
{
    esp_http_client_t *client = parser->data;
    client->current_header_is_value = true;
    return append_header(&client->current_header_value, at, length);
}

'''
source = source[:start] + callbacks + source[end:]
# Whitespace differs between SDK checkouts; anchor the actual declaration.
import re
source, count = re.subn(r'(char\s+\*current_header_key;)', r'\1\n    bool current_header_is_value;', source)
assert count == 1, 'Unexpected SDK header state layout'
needle = 'static int http_on_headers_complete(http_parser *parser)\n{\n    esp_http_client_handle_t client = parser->data;'
assert source.count(needle) == 1
source = source.replace(needle, needle + '\n    finish_header(client);')
# Stop on malformed/oversized headers instead of continuing after parser errors.
needle = 'http_parser_execute(client->parser, client->parser_settings, buffer->data, buffer->len);'
assert source.count(needle) == 1
source = source.replace(needle, needle + '\n        if (HTTP_PARSER_ERRNO(client->parser) != HPE_OK) return ESP_FAIL;')
Path(sys.argv[2]).write_text(source)
