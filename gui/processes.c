#include "processes.h"
#include "discovery.h"
#include <gio/gdesktopappinfo.h>
#include <string.h>

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
    GIcon *icon
) {
    StraitProcess *p = g_object_new(STRAIT_TYPE_PROCESS, NULL);
    p->name = g_strdup(name);
    p->pid = pid;
    p->connections = connections;
    p->protocols = g_strdup(protocols);
    p->exe_path = g_strdup(exe_path);
    p->icon = icon ? g_object_ref(icon) : g_themed_icon_new("application-x-executable");
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

static GtkColumnViewColumn *
make_column(const gchar *title, GCallback setup_cb, GCallback bind_cb, gint min_chars) {
    GtkListItemFactory *factory = gtk_signal_list_item_factory_new();
    g_signal_connect(factory, "setup", setup_cb, GINT_TO_POINTER(min_chars));
    g_signal_connect(factory, "bind", bind_cb, NULL);

    GtkColumnViewColumn *col = gtk_column_view_column_new(title, factory);
    gtk_column_view_column_set_resizable(col, TRUE);
    return col;
}

static void clear_store(GListStore *store) { g_list_store_remove_all(store); }

static GListStore *get_store_from_view(GtkWidget *view) {
    return G_LIST_STORE(g_object_get_data(G_OBJECT(view), "store"));
}

static void populate_store(GListStore *store) {
    process_list *list = NULL;
    discovery_code code = get_network_processes(&list);

    clear_store(store);

    if (code != DISCOVERY_OK) {
        g_warning("Failed to get network processes: %s", discovery_code_string(code));
        return;
    }

    for (size_t i = 0; i < list->count; i++) {
        process_info *p = &list->processes[i];
        char protocols[16];

        if (p->has_tcp && p->has_udp) {
            strncpy(protocols, "TCP/UDP", sizeof(protocols) - 1);
        } else if (p->has_tcp) {
            strncpy(protocols, "TCP", sizeof(protocols) - 1);
        } else if (p->has_udp) {
            strncpy(protocols, "UDP", sizeof(protocols) - 1);
        } else {
            strncpy(protocols, "-", sizeof(protocols) - 1);
        }
        protocols[sizeof(protocols) - 1] = '\0';

        g_autoptr(GIcon) icon = lookup_icon(p->exe_path, p->process_name, p->pid);
        g_autoptr(StraitProcess) proc = strait_process_new(
            p->process_name, (gint)p->pid, p->num_connections, protocols, p->exe_path, icon
        );
        g_list_store_append(store, G_OBJECT(proc));
    }

    destroy_process_list(list);
}

static gboolean on_refresh_timeout_cb(gpointer user_data) {
    GtkWidget *view = GTK_WIDGET(user_data);
    populate_store(get_store_from_view(view));
    return G_SOURCE_CONTINUE;
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
    strait_processes_view_stop_refresh(view);

    guint id = g_timeout_add_seconds(interval_sec, on_refresh_timeout_cb, view);
    g_object_set_data(G_OBJECT(view), "timeout-id", GUINT_TO_POINTER(id));
}

void strait_processes_view_stop_refresh(GtkWidget *view) {
    guint id = GPOINTER_TO_UINT(g_object_get_data(G_OBJECT(view), "timeout-id"));
    if (id != 0) {
        g_source_remove(id);
        g_object_set_data(G_OBJECT(view), "timeout-id", GUINT_TO_POINTER(0));
    }
}
