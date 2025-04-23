#include "modsec.h"
#include <stdio.h>
#include <string.h>

int detect_command_injection(const char *input) {
  const char *suspicious[] = {";", "&&", "|", "`", "$(", NULL};
  for (int i = 0; suspicious[i]; i++) {
    if (strstr(input, suspicious[i])) {
      return 1;
    }
  }
  return 0;
}

void normalize_url(char *url) {
  char *src = url, *dst = url;
  while (*src) {
    if (*src == '/' && *(src + 1) == '/') {
      src++;
      continue;
    }
    if (strncmp(src, "/./", 3) == 0) {
      src += 2;
      continue;
    }
    if (strncmp(src, "/../", 4) == 0) {
      while (dst > url && *--dst != '/');
      src += 3;
      continue;
    }
    *dst++ = *src++;
  }
  *dst = '\0';
}


  
int has_encoded_null_byte(const char *buf, size_t len) {
    for (size_t i = 0; i + 2 < len; i++) {
        if (buf[i] == '%' && buf[i + 1] == '0' && buf[i + 2] == '0') {
        return 1;
        }
    }
    return 0;
}

int modsec_inspect(const char *raw, const char *uri, const char *payload) {
    fprintf(stderr, "[modsec] raw: %s\n", raw);
    fprintf(stderr, "[modsec] uri: %s\n", uri);
    fprintf(stderr, "[modsec] pay: %s\n", payload);



    if (has_encoded_null_byte(uri, strlen(uri))) {
        fprintf(stderr, "[modsec] Encoded NULL byte (%%00) detected in request\n");
    return 1;
    }

  char normalized_uri[1024];
  strncpy(normalized_uri, uri, sizeof(normalized_uri) - 1);
  normalized_uri[sizeof(normalized_uri) - 1] = '\0';

  normalize_url(normalized_uri);

  if (strcmp(normalized_uri, uri) != 0) {
    fprintf(stderr, "[modsec] Normalized URI mismatch: %s != %s\n", uri, normalized_uri);
    return 1;
  }

  if (detect_command_injection(uri)) {
    fprintf(stderr, "[modsec] Suspicious pattern in URI: %s\n", uri);
    return 1;
  }

  if (payload && detect_command_injection(payload)) {
    fprintf(stderr, "[modsec] Suspicious pattern in payload\n");
    return 1;
  }

  return 0;
}