#include "backend.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

struct StraitBackend {
    GPid pid;
    GIOChannel *stdin_channel;
    GIOChannel *stdout_channel;
};

gboolean backend_start(StraitBackend **backend, const gchar *executable_path) {
    gchar *argv[] = {"pkexec", (gchar *)executable_path, "--strait-privileged", NULL};
    gint stdin_fd, stdout_fd;
    GError *error = NULL;
    GPid pid;

    gboolean ok = g_spawn_async_with_pipes(
        NULL,
        argv,
        NULL,
        G_SPAWN_DO_NOT_REAP_CHILD | G_SPAWN_SEARCH_PATH,
        NULL,
        NULL,
        &pid,
        &stdin_fd,
        &stdout_fd,
        NULL,
        &error
    );

    if (!ok) {
        g_error_free(error);
        return FALSE;
    }

    *backend = g_new0(StraitBackend, 1);
    (*backend)->pid = pid;
    (*backend)->stdin_channel = g_io_channel_unix_new(stdin_fd);
    (*backend)->stdout_channel = g_io_channel_unix_new(stdout_fd);
    g_io_channel_set_encoding((*backend)->stdin_channel, "UTF-8", NULL);
    g_io_channel_set_encoding((*backend)->stdout_channel, "UTF-8", NULL);

    gchar *line = NULL;
    gsize len = 0;
    GIOStatus status = g_io_channel_read_line((*backend)->stdout_channel, &line, &len, NULL, NULL);
    if (status != G_IO_STATUS_NORMAL || !line || strncmp(line, BACKEND_RESPONSE_READY, 5) != 0) {
        g_free(line);
        g_io_channel_unref((*backend)->stdin_channel);
        g_io_channel_unref((*backend)->stdout_channel);
        g_spawn_close_pid(pid);
        g_free(*backend);
        *backend = NULL;
        return FALSE;
    }
    g_free(line);

    return TRUE;
}

void backend_stop(StraitBackend *backend) {
    if (!backend)
        return;

    if (backend->stdin_channel) {
        gchar *quit_cmd = g_strdup_printf("%s\n", BACKEND_CMD_QUIT);
        g_io_channel_write_chars(backend->stdin_channel, quit_cmd, -1, NULL, NULL);
        g_io_channel_flush(backend->stdin_channel, NULL);
        g_free(quit_cmd);
        g_io_channel_unref(backend->stdin_channel);
    }

    if (backend->stdout_channel) {
        g_io_channel_unref(backend->stdout_channel);
    }

    if (backend->pid > 0) {
        int status;
        waitpid(backend->pid, &status, 0);
        g_spawn_close_pid(backend->pid);
    }

    g_free(backend);
}

gchar *backend_list(StraitBackend *backend) {
    if (!backend || !backend->stdin_channel || !backend->stdout_channel)
        return NULL;

    gchar *cmd = g_strdup_printf("%s\n", BACKEND_CMD_LIST);
    g_io_channel_write_chars(backend->stdin_channel, cmd, -1, NULL, NULL);
    g_io_channel_flush(backend->stdin_channel, NULL);
    g_free(cmd);

    GString *response = g_string_new(NULL);
    gchar *line = NULL;
    gsize len = 0;
    GIOStatus status;

    status = g_io_channel_read_line(backend->stdout_channel, &line, &len, NULL, NULL);
    if (status != G_IO_STATUS_NORMAL) {
        g_string_free(response, TRUE);
        return NULL;
    }

    g_string_append(response, line);
    g_free(line);

    int count = atoi(response->str);
    if (count <= 0) {
        return g_string_free(response, FALSE);
    }

    for (int i = 0; i < count * 2; i++) {
        status = g_io_channel_read_line(backend->stdout_channel, &line, &len, NULL, NULL);
        if (status != G_IO_STATUS_NORMAL)
            break;
        g_string_append(response, line);
        g_free(line);
    }

    return g_string_free(response, FALSE);
}
