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

static void cmd_list(void) {
    process_list *list = NULL;
    if (get_network_processes(&list) != DISCOVERY_OK) {
        printf("%s\n", BACKEND_RESPONSE_ERROR);
        fflush(stdout);
        return;
    }

    printf("%zu\n", list->count);
    for (size_t i = 0; i < list->count; i++) {
        uint64_t upload = 0;
        uint64_t download = 0;
        get_rate_limits_from_cgroup(list->processes[i].pid, &upload, &download);
        printf(
            "%d %d %d %d %lu %lu %s\n%s\n",
            list->processes[i].pid,
            list->processes[i].num_connections,
            list->processes[i].has_tcp,
            list->processes[i].has_udp,
            (unsigned long)upload,
            (unsigned long)download,
            list->processes[i].process_name,
            list->processes[i].exe_path
        );
    }
    fflush(stdout);
    destroy_process_list(list);
}

static int run_privileged(void) {
    ratelimit_init();
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("%s\n", BACKEND_RESPONSE_READY);

    char line[1024];
    while (fgets(line, sizeof(line), stdin)) {
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n')
            line[len - 1] = '\0';

        if (strcmp(line, BACKEND_CMD_LIST) == 0) {
            cmd_list();
            continue;
        }

        if (strcmp(line, BACKEND_CMD_QUIT) == 0)
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
    gtk_window_set_default_size(GTK_WINDOW(window), 900, 600);
    gtk_widget_set_size_request(window, 700, 400);

    GtkWidget *toolbar_view = adw_toolbar_view_new();
    adw_application_window_set_content(ADW_APPLICATION_WINDOW(window), toolbar_view);

    AdwHeaderBar *header_bar = ADW_HEADER_BAR(adw_header_bar_new());
    adw_toolbar_view_add_top_bar(ADW_TOOLBAR_VIEW(toolbar_view), GTK_WIDGET(header_bar));

    GtkWidget *refresh_button = gtk_button_new_from_icon_name("view-refresh-symbolic");
    gtk_widget_set_tooltip_text(refresh_button, "Refresh");

    GtkWidget *processes_view = strait_processes_view_new(raw_data);
    g_object_set_data(G_OBJECT(window), "processes-view", processes_view);
    g_signal_connect(refresh_button, "clicked", G_CALLBACK(on_refresh_clicked), processes_view);
    adw_header_bar_pack_end(header_bar, refresh_button);

    adw_toolbar_view_set_content(ADW_TOOLBAR_VIEW(toolbar_view), processes_view);

    g_signal_connect(window, "close-request", G_CALLBACK(on_close_request), app);

    gtk_window_present(GTK_WINDOW(window));
    g_free(raw_data);
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], STRAIT_PRIVILEGED) == 0) {
        return run_privileged();
    }

    AdwApplication *app = adw_application_new("com.example.strait", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(on_activate), NULL);
    int status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);
    return status;
}
