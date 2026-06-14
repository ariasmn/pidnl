#ifndef BACKEND_H
#define BACKEND_H

#include <glib.h>
#include <stdint.h>
#include <sys/types.h>

#define BACKEND_CMD_LIST 0
#define BACKEND_CMD_LIMIT 1
#define BACKEND_CMD_QUIT 2
#define BACKEND_RESPONSE_READY 0
#define BACKEND_RESPONSE_OK 1
#define BACKEND_RESPONSE_ERROR 2

typedef struct StraitBackend StraitBackend;

gboolean backend_start(StraitBackend **backend, const gchar *executable_path);
void backend_stop(StraitBackend *backend);
gchar *backend_list(StraitBackend *backend);
gboolean
backend_set_limit(StraitBackend *backend, pid_t pid, uint32_t upload_kbps, uint32_t download_kbps);
#endif
