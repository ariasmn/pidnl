#include "processes.h"
#include "discovery.h"
#include "ratelimit.h"
#include <gio/gdesktopappinfo.h>
#include <string.h>
#include <unistd.h>

static GList *all_apps = NULL;

static GIcon *lookup_icon(const gchar *exe_path, const gchar *process_name, pid_t pid) {
    if (!all_apps)
        all_apps = g_app_info_get_all();

    const gchar *exe_base = exe_path ? strrchr(exe_path, '/') : NULL;
    exe_base = exe_base ? exe_base + 1 : exe_path;

    // First pass: try to match by executable name
    for (GList *l = all_apps; l; l = l->next) {
        GAppInfo *info = l->data;
        const gchar *exec = g_app_info_get_executable(info);
        if (!exec)
            continue;

        const gchar *exec_base = strrchr(exec, '/');
        exec_base = exec_base ? exec_base + 1 : exec;

        if ((exe_base && strcmp(exe_base, exec_base) == 0) ||
            (process_name && strcmp(process_name, exec_base) == 0)) {
            GIcon *icon = g_app_info_get_icon(info);
            return icon ? g_object_ref(icon) : g_themed_icon_new("application-x-executable");
        }
    }

    // Second pass: try to match Flatpak apps by cgroup
    gchar cgroup_path[64];
    g_snprintf(cgroup_path, sizeof(cgroup_path), "/proc/%d/cgroup", pid);
    g_autofree gchar *cgroup = NULL;
    if (!g_file_get_contents(cgroup_path, &cgroup, NULL, NULL))
        return g_themed_icon_new("application-x-executable");

    for (GList *l = all_apps; l; l = l->next) {
        GAppInfo *info = l->data;
        if (!G_IS_DESKTOP_APP_INFO(info))
            continue;

        g_autofree gchar *flatpak_id =
            g_desktop_app_info_get_string(G_DESKTOP_APP_INFO(info), "X-Flatpak");
        if (flatpak_id && strstr(cgroup, flatpak_id)) {
            GIcon *icon = g_app_info_get_icon(info);
            return icon ? g_object_ref(icon) : g_themed_icon_new("application-x-executable");
        }
    }

    return g_themed_icon_new("application-x-executable");
}

struct _StraitProcess {
    GObject parent_instance;
    gchar *name;
    gint pid;
    gint connections;
    gchar *protocols;
    gchar *exe_path;
    GIcon *icon;
    guint64 upload_bps;
    guint64 download_bps;
};

G_DEFINE_TYPE(StraitProcess, strait_process, G_TYPE_OBJECT)

static void strait_process_finalize(GObject *object) {
    StraitProcess *self = STRAIT_PROCESS(object);
    g_free(self->name);
    g_free(self->protocols);
    g_free(self->exe_path);
    g_clear_object(&self->icon);
    G_OBJECT_CLASS(strait_process_parent_class)->finalize(object);
}

static void strait_process_class_init(StraitProcessClass *klass) {
    G_OBJECT_CLASS(klass)->finalize = strait_process_finalize;
}

static void strait_process_init(StraitProcess *self) { (void)self; }

static StraitProcess *strait_process_new(
    const gchar *name,
    gint pid,
    gint connections,
    const gchar *protocols,
    const gchar *exe_path,
    GIcon *icon,
    guint64 upload_bps,
    guint64 download_bps
) {
    StraitProcess *p = g_object_new(STRAIT_TYPE_PROCESS, NULL);
    p->name = g_strdup(name);
    p->pid = pid;
    p->connections = connections;
    p->protocols = g_strdup(protocols);
    p->exe_path = g_strdup(exe_path);
    p->icon = icon ? g_object_ref(icon) : g_themed_icon_new("application-x-executable");
    p->upload_bps = upload_bps;
    p->download_bps = download_bps;
    return p;
}

static void
setup_column_cb(GtkSignalListItemFactory *factory, GtkListItem *item, gpointer user_data) {
    (void)factory;
    gint min_chars = GPOINTER_TO_INT(user_data);
    GtkWidget *insc = gtk_inscription_new(NULL);
    gtk_inscription_set_min_chars(GTK_INSCRIPTION(insc), min_chars);
    gtk_inscription_set_xalign(GTK_INSCRIPTION(insc), 0.0);
    gtk_inscription_set_text_overflow(GTK_INSCRIPTION(insc), GTK_INSCRIPTION_OVERFLOW_CLIP);
    gtk_widget_set_hexpand(insc, TRUE);
    gtk_list_item_set_child(item, insc);
}

static void
setup_name_cb(GtkSignalListItemFactory *factory, GtkListItem *item, gpointer user_data) {
    (void)factory;
    (void)user_data;

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);

    GtkWidget *image = gtk_image_new();
    gtk_image_set_pixel_size(GTK_IMAGE(image), 16);
    gtk_box_append(GTK_BOX(box), image);

    GtkWidget *insc = gtk_inscription_new(NULL);
    gtk_inscription_set_min_chars(GTK_INSCRIPTION(insc), 20);
    gtk_inscription_set_xalign(GTK_INSCRIPTION(insc), 0.0);
    gtk_inscription_set_text_overflow(GTK_INSCRIPTION(insc), GTK_INSCRIPTION_OVERFLOW_CLIP);
    gtk_widget_set_hexpand(insc, TRUE);
    gtk_box_append(GTK_BOX(box), insc);

    gtk_list_item_set_child(item, box);
}

static void bind_name_cb(GtkSignalListItemFactory *factory, GtkListItem *item) {
    (void)factory;
    StraitProcess *proc = STRAIT_PROCESS(gtk_list_item_get_item(item));
    GtkWidget *box = gtk_list_item_get_child(item);
    GtkWidget *image = gtk_widget_get_first_child(box);
    GtkWidget *insc = gtk_widget_get_last_child(box);
    gtk_image_set_from_gicon(GTK_IMAGE(image), proc->icon);
    gtk_inscription_set_text(GTK_INSCRIPTION(insc), proc->name);
}

static void bind_pid_cb(GtkSignalListItemFactory *factory, GtkListItem *item) {
    (void)factory;
    StraitProcess *proc = STRAIT_PROCESS(gtk_list_item_get_item(item));
    GtkWidget *insc = gtk_list_item_get_child(item);
    g_autofree gchar *t = g_strdup_printf("%d", proc->pid);
    gtk_inscription_set_text(GTK_INSCRIPTION(insc), t);
}

static void bind_connections_cb(GtkSignalListItemFactory *factory, GtkListItem *item) {
    (void)factory;
    StraitProcess *proc = STRAIT_PROCESS(gtk_list_item_get_item(item));
    GtkWidget *insc = gtk_list_item_get_child(item);
    g_autofree gchar *t = g_strdup_printf("%d", proc->connections);
    gtk_inscription_set_text(GTK_INSCRIPTION(insc), t);
}

static void bind_protocols_cb(GtkSignalListItemFactory *factory, GtkListItem *item) {
    (void)factory;
    StraitProcess *proc = STRAIT_PROCESS(gtk_list_item_get_item(item));
    GtkWidget *insc = gtk_list_item_get_child(item);
    gtk_inscription_set_text(GTK_INSCRIPTION(insc), proc->protocols);
}

static void bind_exe_path_cb(GtkSignalListItemFactory *factory, GtkListItem *item) {
    (void)factory;
    StraitProcess *proc = STRAIT_PROCESS(gtk_list_item_get_item(item));
    GtkWidget *insc = gtk_list_item_get_child(item);
    gtk_inscription_set_text(GTK_INSCRIPTION(insc), proc->exe_path);
}

static void bind_limits_cb(GtkSignalListItemFactory *factory, GtkListItem *item) {
    (void)factory;
    StraitProcess *proc = STRAIT_PROCESS(gtk_list_item_get_item(item));
    GtkWidget *insc = gtk_list_item_get_child(item);

    g_autofree gchar *t;
    if (proc->upload_bps == 0 && proc->download_bps == 0) {
        t = g_strdup("-");
    } else {
        guint64 upload_kbps = (proc->upload_bps * 8) / 1000;
        guint64 download_kbps = (proc->download_bps * 8) / 1000;
        t = g_strdup_printf("%lu / %lu", (unsigned long)upload_kbps, (unsigned long)download_kbps);
    }

    gtk_inscription_set_text(GTK_INSCRIPTION(insc), t);
}

static GtkColumnViewColumn *
make_column(const gchar *title, GCallback setup_cb, GCallback bind_cb, gint min_chars) {
    GtkListItemFactory *factory = gtk_signal_list_item_factory_new();
    g_signal_connect(factory, "setup", setup_cb, GINT_TO_POINTER(min_chars));
    g_signal_connect(factory, "bind", bind_cb, NULL);

    GtkColumnViewColumn *col = gtk_column_view_column_new(title, factory);
    gtk_column_view_column_set_resizable(col, TRUE);
    return col;
}

static void append_process_to_store(
    GListStore *store,
    const char *name,
    pid_t pid,
    int connections,
    int has_tcp,
    int has_udp,
    const char *exe_path,
    guint64 upload_bps,
    guint64 download_bps
) {
    const char *protocols;
    if (has_tcp && has_udp)
        protocols = "TCP/UDP";
    else if (has_tcp)
        protocols = "TCP";
    else if (has_udp)
        protocols = "UDP";
    else
        protocols = "-";

    g_autoptr(GIcon) icon = lookup_icon(exe_path, name, pid);
    g_autoptr(StraitProcess) proc = strait_process_new(
        name, (gint)pid, connections, protocols, exe_path, icon, upload_bps, download_bps
    );
    g_list_store_append(store, G_OBJECT(proc));
}

static void fetch_all_via_pkexec(GListStore *store) {
    gchar *self_exe = g_file_read_link("/proc/self/exe", NULL);
    if (!self_exe)
        return;

    gchar *argv[] = {"pkexec", self_exe, "--strait-dump-all", NULL};
    gchar *stdout_data = NULL;
    gint exit_status = 0;
    GError *error = NULL;

    gboolean spawn_ok = g_spawn_sync(
        NULL,
        argv,
        NULL,
        G_SPAWN_STDERR_TO_DEV_NULL | G_SPAWN_SEARCH_PATH,
        NULL,
        NULL,
        &stdout_data,
        NULL,
        &exit_status,
        &error
    );
    g_free(self_exe);

    if (!spawn_ok || !stdout_data || (WIFEXITED(exit_status) && WEXITSTATUS(exit_status) != 0)) {
        g_free(stdout_data);
        if (error)
            g_error_free(error);
        return;
    }

    gchar **lines = g_strsplit(stdout_data, "\n", -1);
    g_free(stdout_data);

    if (!lines[0] || !*lines[0]) {
        g_strfreev(lines);
        return;
    }

    int count = atoi(lines[0]);
    if (count <= 0) {
        g_strfreev(lines);
        return;
    }

    int idx = 1;
    for (int i = 0; i < count && lines[idx] && lines[idx + 1]; i++) {
        int pid, connections, has_tcp, has_udp;
        unsigned long upload, download;
        char name[TS_COMM_LEN] = {0};
        if (sscanf(
                lines[idx],
                "%d %d %d %d %lu %lu %[^\n]",
                &pid,
                &connections,
                &has_tcp,
                &has_udp,
                &upload,
                &download,
                name
            ) == 7) {
            append_process_to_store(
                store,
                name,
                (pid_t)pid,
                connections,
                has_tcp,
                has_udp,
                lines[idx + 1],
                upload,
                download
            );
        }
        idx += 2;
    }

    g_strfreev(lines);
}

static void populate_from_root(GListStore *store) {
    process_list *list = NULL;
    if (get_network_processes(&list) != DISCOVERY_OK) {
        g_warning("Failed to get network processes");
        return;
    }
    for (size_t i = 0; i < list->count; i++) {
        process_info *p = &list->processes[i];
        uint64_t upload = 0, download = 0;
        get_rate_limits_from_cgroup(p->pid, &upload, &download);
        append_process_to_store(
            store,
            p->process_name,
            p->pid,
            p->num_connections,
            p->has_tcp,
            p->has_udp,
            p->exe_path,
            upload,
            download
        );
    }
    destroy_process_list(list);
}

static void clear_store(GListStore *store) { g_list_store_remove_all(store); }

static GListStore *get_store_from_view(GtkWidget *view) {
    return G_LIST_STORE(g_object_get_data(G_OBJECT(view), "store"));
}

static void populate_store(GListStore *store) {
    clear_store(store);

    if (geteuid() == 0) {
        populate_from_root(store);
    } else {
        fetch_all_via_pkexec(store);
    }
}

GtkWidget *strait_processes_view_new(void) {
    GListStore *store = g_list_store_new(STRAIT_TYPE_PROCESS);

    g_autoptr(GtkNoSelection) selection = gtk_no_selection_new(G_LIST_MODEL(store));
    GtkWidget *column_view = gtk_column_view_new(GTK_SELECTION_MODEL(selection));

    gtk_column_view_append_column(
        GTK_COLUMN_VIEW(column_view),
        make_column("Name", G_CALLBACK(setup_name_cb), G_CALLBACK(bind_name_cb), 0)
    );
    gtk_column_view_append_column(
        GTK_COLUMN_VIEW(column_view),
        make_column("PID", G_CALLBACK(setup_column_cb), G_CALLBACK(bind_pid_cb), 10)
    );
    gtk_column_view_append_column(
        GTK_COLUMN_VIEW(column_view),
        make_column("Connections", G_CALLBACK(setup_column_cb), G_CALLBACK(bind_connections_cb), 12)
    );
    gtk_column_view_append_column(
        GTK_COLUMN_VIEW(column_view),
        make_column("Protocols", G_CALLBACK(setup_column_cb), G_CALLBACK(bind_protocols_cb), 10)
    );
    gtk_column_view_append_column(
        GTK_COLUMN_VIEW(column_view),
        make_column("Limits", G_CALLBACK(setup_column_cb), G_CALLBACK(bind_limits_cb), 18)
    );
    gtk_column_view_append_column(
        GTK_COLUMN_VIEW(column_view),
        make_column("Command Line", G_CALLBACK(setup_column_cb), G_CALLBACK(bind_exe_path_cb), 30)
    );

    GtkWidget *scrolled = gtk_scrolled_window_new();
    gtk_scrolled_window_set_policy(
        GTK_SCROLLED_WINDOW(scrolled), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC
    );
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled), column_view);
    gtk_widget_set_vexpand(scrolled, TRUE);
    gtk_widget_set_hexpand(scrolled, TRUE);

    g_object_set_data_full(G_OBJECT(scrolled), "store", store, g_object_unref);

    populate_store(store);

    return scrolled;
}

void strait_processes_view_refresh(GtkWidget *view) { populate_store(get_store_from_view(view)); }

void strait_processes_view_start_refresh(GtkWidget *view, guint interval_sec) {
    (void)view;
    (void)interval_sec;
}

void strait_processes_view_stop_refresh(GtkWidget *view) { (void)view; }
