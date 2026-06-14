#ifndef BACKEND_H
#define BACKEND_H

#include <glib.h>

#define BACKEND_CMD_LIST "LIST"
#define BACKEND_CMD_LIMIT "LIMIT"
#define BACKEND_CMD_QUIT "QUIT"
#define BACKEND_RESPONSE_READY "READY"
#define BACKEND_RESPONSE_OK "OK"
#define BACKEND_RESPONSE_ERROR "ERROR"

typedef struct StraitBackend StraitBackend;

gboolean backend_start(StraitBackend **backend, const gchar *executable_path);
void backend_stop(StraitBackend *backend);
gchar *backend_list(StraitBackend *backend);
gboolean
backend_set_limit(StraitBackend *backend, gint pid, guint upload_kbps, guint download_kbps);
#endif
