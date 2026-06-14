#include <adwaita.h>
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "backend.h"
#include "discovery.h"
#include "processes.h"
#include "ratelimit.h"

#define STRAIT_PRIVILEGED "--strait-privileged"

static StraitBackend *backend = NULL;

static void handle_list_cmd(void) {
    process_list *list = NULL;
    if (get_network_processes(&list) != DISCOVERY_OK) {
        printf("%d\n", BACKEND_RESPONSE_ERROR);
        fflush(stdout);
        return;
    }

    printf("%zu\n", list->count);
    for (size_t i = 0; i < list->count; i++) {
        uint32_t upload_kbps = RATELIMIT_UNLIMITED;
        uint32_t download_kbps = RATELIMIT_UNLIMITED;
        get_rate_limits_from_cgroup(list->processes[i].pid, &upload_kbps, &download_kbps);
        printf(
            "%d %d %d %d %u %u %s\n%s\n",
            list->processes[i].pid,
            list->processes[i].num_connections,
            list->processes[i].has_tcp,
            list->processes[i].has_udp,
            upload_kbps,
            download_kbps,
            list->processes[i].process_name,
            list->processes[i].exe_path
        );
    }
    fflush(stdout);
    destroy_process_list(list);
}

static void handle_limit_cmd(pid_t pid, uint32_t upload, uint32_t download) {
    ratelimit_code rc;
    if (upload == RATELIMIT_UNLIMITED && download == RATELIMIT_UNLIMITED) {
        // TODO: Check if it makes sense to clean using the monitor itself, instead of doing this.
        rc = unregister_rate_limiter_by_pid(pid);
        if (rc == RATELIMIT_CGROUP_NOT_FOUND)
            rc = RATELIMIT_OK;
    } else {
        rate_limit_config cfg = {.upload_kbps = upload, .download_kbps = download};
        rc = limit_process_bandwidth(pid, cfg);
    }

    printf("%d\n", rc == RATELIMIT_OK ? BACKEND_RESPONSE_OK : BACKEND_RESPONSE_ERROR);
    fflush(stdout);
}

static void handle_clean_cmd(void) {
    ratelimit_code rc = ratelimit_cleanup_all();
    printf("%d\n", rc == RATELIMIT_OK ? BACKEND_RESPONSE_OK : BACKEND_RESPONSE_ERROR);
    fflush(stdout);
}

static int run_privileged(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    ratelimit_code rc = ratelimit_init();
    if (rc != RATELIMIT_OK) {
        fprintf(stderr, "strait: ratelimit_init failed: %s\n", ratelimit_code_string(rc));
        printf("%d\n", BACKEND_RESPONSE_ERROR);
        return EXIT_FAILURE;
    }

    printf("%d\n", BACKEND_RESPONSE_READY);

    char line[64];
    while (fgets(line, sizeof(line), stdin)) {
        int cmd;
        if (sscanf(line, "%d", &cmd) != 1)
            continue;

        if (cmd == BACKEND_CMD_LIST) {
            handle_list_cmd();
            continue;
        }

        if (cmd == BACKEND_CMD_LIMIT) {
            gint pid;
            uint32_t upload, download;
            if (sscanf(line, "%d %d %u %u", &cmd, &pid, &upload, &download) == 4)
                handle_limit_cmd(pid, upload, download);
            else
                printf("%d\n", BACKEND_RESPONSE_ERROR);
            fflush(stdout);
            continue;
        }

        if (cmd == BACKEND_CMD_CLEAN) {
            handle_clean_cmd();
            continue;
        }

        if (cmd == BACKEND_CMD_QUIT)
            break;
    }

    return EXIT_SUCCESS;
}

static void on_refresh_clicked(GtkButton *button, gpointer user_data) {
    (void)button;
    GtkWidget *view = GTK_WIDGET(user_data);

    gchar *raw_data = backend_list(backend);
    if (raw_data) {
        strait_processes_view_refresh(view, raw_data);
        g_free(raw_data);
    }
}

static void on_clean_response(AdwAlertDialog *dialog, const char *response, gpointer user_data) {
    (void)dialog;
    if (g_strcmp0(response, "clean") != 0)
        return;

    GtkWidget *view = GTK_WIDGET(user_data);
    if (!backend_clean(backend))
        return;

    gchar *raw_data = backend_list(backend);
    if (raw_data) {
        strait_processes_view_refresh(view, raw_data);
        g_free(raw_data);
    }
}

static void on_clean_clicked(GtkButton *button, gpointer user_data) {
    AdwAlertDialog *dialog = ADW_ALERT_DIALOG(adw_alert_dialog_new(
        "Clean up all rate limits?", "This will remove all rate limits created by Strait."
    ));

    adw_alert_dialog_add_responses(dialog, "cancel", "Cancel", "clean", "Clean", NULL);
    adw_alert_dialog_set_response_appearance(dialog, "clean", ADW_RESPONSE_DESTRUCTIVE);
    adw_alert_dialog_set_default_response(dialog, "cancel");
    adw_alert_dialog_set_close_response(dialog, "cancel");

    g_signal_connect(dialog, "response", G_CALLBACK(on_clean_response), user_data);
    adw_dialog_present(ADW_DIALOG(dialog), GTK_WIDGET(gtk_widget_get_root(GTK_WIDGET(button))));
}

static gboolean on_close_request(GtkWindow *window, gpointer user_data) {
    (void)window;
    GtkApplication *app = GTK_APPLICATION(user_data);
    backend_stop(backend);
    backend = NULL;
    g_application_quit(G_APPLICATION(app));
    return TRUE;
}

static void on_activate(GtkApplication *app, gpointer user_data) {
    (void)user_data;

    gchar *self_exe = g_file_read_link("/proc/self/exe", NULL);
    if (!self_exe) {
        g_application_quit(G_APPLICATION(app));
        return;
    }

    if (!backend_start(&backend, self_exe)) {
        g_free(self_exe);
        g_application_quit(G_APPLICATION(app));
        return;
    }
    g_free(self_exe);

    gchar *raw_data = backend_list(backend);
    if (!raw_data) {
        backend_stop(backend);
        backend = NULL;
        g_application_quit(G_APPLICATION(app));
        return;
    }

    GtkWidget *window = adw_application_window_new(GTK_APPLICATION(app));
    gtk_window_set_title(GTK_WINDOW(window), "Strait");
    gtk_window_set_default_size(GTK_WINDOW(window), 1200, 600);
    gtk_widget_set_size_request(window, 700, 400);

    GtkWidget *toolbar_view = adw_toolbar_view_new();
    adw_application_window_set_content(ADW_APPLICATION_WINDOW(window), toolbar_view);

    AdwHeaderBar *header_bar = ADW_HEADER_BAR(adw_header_bar_new());
    adw_toolbar_view_add_top_bar(ADW_TOOLBAR_VIEW(toolbar_view), GTK_WIDGET(header_bar));

    GtkWidget *refresh_button = gtk_button_new_from_icon_name("view-refresh-symbolic");
    gtk_widget_set_tooltip_text(refresh_button, "Refresh");

    GtkWidget *processes_view = strait_processes_view_new(raw_data);
    strait_processes_view_set_backend(processes_view, backend);
    g_object_set_data(G_OBJECT(window), "processes-view", processes_view);
    g_signal_connect(refresh_button, "clicked", G_CALLBACK(on_refresh_clicked), processes_view);
    adw_header_bar_pack_end(header_bar, refresh_button);

    GtkWidget *clean_button = gtk_button_new_from_icon_name("user-trash-symbolic");
    gtk_widget_set_tooltip_text(clean_button, "Clean up all rate limits");
    g_signal_connect(clean_button, "clicked", G_CALLBACK(on_clean_clicked), processes_view);
    adw_header_bar_pack_end(header_bar, clean_button);

    adw_toolbar_view_set_content(ADW_TOOLBAR_VIEW(toolbar_view), processes_view);

    g_signal_connect(window, "close-request", G_CALLBACK(on_close_request), app);

    gtk_window_present(GTK_WINDOW(window));
    g_free(raw_data);
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], STRAIT_PRIVILEGED) == 0) {
        return run_privileged();
    }

    AdwApplication *app =
        adw_application_new("io.github.ariasmn.Strait", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(on_activate), NULL);
    int status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);
    return status;
}
