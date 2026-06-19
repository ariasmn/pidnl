#include "processes.h"
#include "ratelimit.h"
#include <gio/gdesktopappinfo.h>
#include <string.h>

static GList *all_apps = NULL;

static GIcon *lookup_icon(const gchar *exe_path, const gchar *process_name, pid_t pid) {
    if (!all_apps) {
        all_apps = g_app_info_get_all();
    }

    const gchar *exe_base = exe_path ? strrchr(exe_path, '/') : NULL;
    exe_base = exe_base ? exe_base + 1 : exe_path;

    for (GList *l = all_apps; l; l = l->next) {
        GAppInfo *info = l->data;
        const gchar *exec = g_app_info_get_executable(info);
        if (!exec) {
            continue;
        }

        const gchar *exec_base = strrchr(exec, '/');
        exec_base = exec_base ? exec_base + 1 : exec;

        if ((exe_base && strcmp(exe_base, exec_base) == 0) ||
            (process_name && strcmp(process_name, exec_base) == 0)) {
            GIcon *icon = g_app_info_get_icon(info);
            return icon ? g_object_ref(icon) : g_themed_icon_new("application-x-executable");
        }
    }

    gchar cgroup_path[64];
    g_snprintf(cgroup_path, sizeof(cgroup_path), "/proc/%d/cgroup", pid);
    g_autofree gchar *cgroup = NULL;
    if (!g_file_get_contents(cgroup_path, &cgroup, NULL, NULL)) {
        return g_themed_icon_new("application-x-executable");
    }

    for (GList *l = all_apps; l; l = l->next) {
        GAppInfo *info = l->data;
        if (!G_IS_DESKTOP_APP_INFO(info)) {
            continue;
        }

        g_autofree gchar *flatpak_id =
            g_desktop_app_info_get_string(G_DESKTOP_APP_INFO(info), "X-Flatpak");
        if (flatpak_id && strstr(cgroup, flatpak_id)) {
            GIcon *icon = g_app_info_get_icon(info);
            return icon ? g_object_ref(icon) : g_themed_icon_new("application-x-executable");
        }
    }

    return g_themed_icon_new("application-x-executable");
}

struct _PIDNLProcess {
    GObject parent_instance;
    gchar *name;
    pid_t pid;
    gint connections;
    gchar *protocols;
    gchar *exe_path;
    GIcon *icon;
    guint32 upload_kbps;
    guint32 download_kbps;
};

G_DEFINE_TYPE(PIDNLProcess, pidnl_process, G_TYPE_OBJECT)

static void pidnl_process_finalize(GObject *object) {
    PIDNLProcess *self = PIDNL_PROCESS(object);
    g_free(self->name);
    g_free(self->protocols);
    g_free(self->exe_path);
    g_clear_object(&self->icon);
    G_OBJECT_CLASS(pidnl_process_parent_class)->finalize(object);
}

static void pidnl_process_class_init(PIDNLProcessClass *klass) {
    G_OBJECT_CLASS(klass)->finalize = pidnl_process_finalize;
}

static void pidnl_process_init(PIDNLProcess *self) {
    (void)self;
}

static PIDNLProcess *pidnl_process_new(
    const gchar *name,
    pid_t pid,
    gint connections,
    const gchar *protocols,
    const gchar *exe_path,
    GIcon *icon,
    guint32 upload_kbps,
    guint32 download_kbps
) {
    PIDNLProcess *p = g_object_new(PIDNL_TYPE_PROCESS, NULL);
    p->name = g_strdup(name);
    p->pid = pid;
    p->connections = connections;
    p->protocols = g_strdup(protocols);
    p->exe_path = g_strdup(exe_path);
    p->icon = icon ? g_object_ref(icon) : g_themed_icon_new("application-x-executable");
    p->upload_kbps = upload_kbps;
    p->download_kbps = download_kbps;
    return p;
}

static GListStore *get_store_from_view(GtkWidget *view) {
    return G_LIST_STORE(g_object_get_data(G_OBJECT(view), "store"));
}

static PIDNLBackend *get_backend_from_view(GtkWidget *view) {
    return g_object_get_data(G_OBJECT(view), "backend");
}

static PIDNLProcess *find_process_by_pid(GListStore *store, pid_t pid) {
    guint n = g_list_model_get_n_items(G_LIST_MODEL(store));
    for (guint i = 0; i < n; i++) {
        g_autoptr(PIDNLProcess) proc = PIDNL_PROCESS(g_list_model_get_item(G_LIST_MODEL(store), i));
        if (proc->pid == pid) {
            return g_object_ref(proc);
        }
    }
    return NULL;
}

static gboolean parse_limit_value(const gchar *text, guint *out) {
    // Empty, "-", or "-1" all mean unlimited; no other negative is valid.
    if (g_strcmp0(text, "") == 0 || g_strcmp0(text, "-") == 0 || g_strcmp0(text, "-1") == 0) {
        *out = RATELIMIT_UNLIMITED;
        return TRUE;
    }

    gchar *endptr = NULL;
    gint64 value = g_ascii_strtoll(text, &endptr, 10);
    if (endptr == text || *endptr != '\0' || value < 0) {
        return FALSE;
    }

    // RATELIMIT_UNLIMITED is the reserved sentinel, so a real limit caps one
    // below it; anything larger (including overflowing input) clamps to that max.
    if (value >= RATELIMIT_UNLIMITED) {
        value = RATELIMIT_UNLIMITED - 1;
    }

    *out = (guint)value;
    return TRUE;
}

// Render a limit into its entry: empty for unlimited, the number otherwise.
static void set_entry_to_value(GtkEditable *editable, guint value) {
    if (value == RATELIMIT_UNLIMITED) {
        gtk_editable_set_text(editable, "");
        return;
    }
    g_autofree gchar *t = g_strdup_printf("%u", value);
    gtk_editable_set_text(editable, t);
}

static void apply_limit(GtkEditable *editable) {
    GtkWidget *entry = GTK_WIDGET(editable);
    pid_t pid = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(entry), "pid"));
    guint direction = GPOINTER_TO_UINT(g_object_get_data(G_OBJECT(entry), "direction"));
    GtkWidget *view = gtk_widget_get_ancestor(entry, GTK_TYPE_SCROLLED_WINDOW);

    if (!view || pid <= 0) {
        return;
    }

    PIDNLBackend *backend = get_backend_from_view(view);
    GListStore *store = get_store_from_view(view);
    if (!backend || !store) {
        return;
    }

    g_autoptr(PIDNLProcess) proc = find_process_by_pid(store, pid);
    guint upload = proc ? proc->upload_kbps : RATELIMIT_UNLIMITED;
    guint download = proc ? proc->download_kbps : RATELIMIT_UNLIMITED;
    guint current = direction == DIRECTION_UPLOAD ? upload : download;

    g_autofree gchar *trimmed = g_strdup(gtk_editable_get_text(editable));
    g_strstrip(trimmed);

    guint new_value = 0;
    if (!parse_limit_value(trimmed, &new_value)) {
        set_entry_to_value(editable, current);
        return;
    }

    if (direction == DIRECTION_UPLOAD) {
        upload = new_value;
    } else {
        download = new_value;
    }

    if (!backend_set_limit(backend, pid, upload, download)) {
        set_entry_to_value(editable, current);
        return;
    }

    if (proc) {
        if (direction == DIRECTION_UPLOAD) {
            proc->upload_kbps = upload;
        } else {
            proc->download_kbps = download;
        }
    }

    set_entry_to_value(editable, new_value);
}

static void on_limit_entry_activate(GtkEntry *entry) {
    apply_limit(GTK_EDITABLE(entry));
}

static void on_limit_focus_leave(GtkEventControllerFocus *controller, gpointer user_data) {
    (void)controller;
    apply_limit(GTK_EDITABLE(user_data));
}

static void clear_focus_from_entry(GtkWidget *entry) {
    GtkRoot *root = gtk_widget_get_root(entry);
    if (root) {
        gtk_root_set_focus(root, NULL);
    }
}

static gboolean on_limit_entry_key_pressed(
    GtkEventControllerKey *controller,
    guint keyval,
    guint keycode,
    GdkModifierType state,
    gpointer user_data
) {
    (void)controller;
    (void)keycode;
    (void)state;

    if (keyval != GDK_KEY_Escape) {
        return GDK_EVENT_PROPAGATE;
    }

    clear_focus_from_entry(GTK_WIDGET(user_data));
    return GDK_EVENT_STOP;
}

static void on_column_view_pressed(
    GtkGestureClick *gesture, gint n_press, gdouble x, gdouble y, gpointer user_data
) {
    (void)gesture;
    (void)n_press;

    GtkWidget *column_view = GTK_WIDGET(user_data);
    GtkWidget *target = gtk_widget_pick(column_view, x, y, GTK_PICK_DEFAULT);

    if (target && gtk_widget_get_ancestor(target, GTK_TYPE_ENTRY)) {
        return;
    }

    GtkRoot *root = gtk_widget_get_root(column_view);
    if (root) {
        gtk_root_set_focus(root, NULL);
    }
}

static GtkWidget *create_limit_entry(void) {
    GtkWidget *entry = gtk_entry_new();
    gtk_entry_set_input_purpose(GTK_ENTRY(entry), GTK_INPUT_PURPOSE_NUMBER);
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry), "Unlimited");
    gtk_entry_set_alignment(GTK_ENTRY(entry), 1.0f);

    GtkEventController *focus = gtk_event_controller_focus_new();
    gtk_widget_add_controller(entry, focus);
    g_signal_connect(focus, "leave", G_CALLBACK(on_limit_focus_leave), entry);
    g_signal_connect(entry, "activate", G_CALLBACK(on_limit_entry_activate), NULL);

    GtkEventController *key = gtk_event_controller_key_new();
    gtk_widget_add_controller(entry, key);
    g_signal_connect(key, "key-pressed", G_CALLBACK(on_limit_entry_key_pressed), entry);

    return entry;
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

static void
setup_upload_limit_cb(GtkSignalListItemFactory *factory, GtkListItem *item, gpointer user_data) {
    (void)factory;
    (void)user_data;
    GtkWidget *entry = create_limit_entry();
    g_object_set_data(G_OBJECT(entry), "direction", GUINT_TO_POINTER(DIRECTION_UPLOAD));
    gtk_list_item_set_child(item, entry);
}

static void
setup_download_limit_cb(GtkSignalListItemFactory *factory, GtkListItem *item, gpointer user_data) {
    (void)factory;
    (void)user_data;
    GtkWidget *entry = create_limit_entry();
    g_object_set_data(G_OBJECT(entry), "direction", GUINT_TO_POINTER(DIRECTION_DOWNLOAD));
    gtk_list_item_set_child(item, entry);
}

static void bind_name_cb(GtkSignalListItemFactory *factory, GtkListItem *item) {
    (void)factory;
    PIDNLProcess *proc = PIDNL_PROCESS(gtk_list_item_get_item(item));
    GtkWidget *box = gtk_list_item_get_child(item);
    GtkWidget *image = gtk_widget_get_first_child(box);
    GtkWidget *insc = gtk_widget_get_last_child(box);
    gtk_image_set_from_gicon(GTK_IMAGE(image), proc->icon);
    gtk_inscription_set_text(GTK_INSCRIPTION(insc), proc->name);
}

static void bind_pid_cb(GtkSignalListItemFactory *factory, GtkListItem *item) {
    (void)factory;
    PIDNLProcess *proc = PIDNL_PROCESS(gtk_list_item_get_item(item));
    GtkWidget *insc = gtk_list_item_get_child(item);
    g_autofree gchar *t = g_strdup_printf("%d", proc->pid);
    gtk_inscription_set_text(GTK_INSCRIPTION(insc), t);
}

static void bind_connections_cb(GtkSignalListItemFactory *factory, GtkListItem *item) {
    (void)factory;
    PIDNLProcess *proc = PIDNL_PROCESS(gtk_list_item_get_item(item));
    GtkWidget *insc = gtk_list_item_get_child(item);
    g_autofree gchar *t = g_strdup_printf("%d", proc->connections);
    gtk_inscription_set_text(GTK_INSCRIPTION(insc), t);
}

static void bind_protocols_cb(GtkSignalListItemFactory *factory, GtkListItem *item) {
    (void)factory;
    PIDNLProcess *proc = PIDNL_PROCESS(gtk_list_item_get_item(item));
    GtkWidget *insc = gtk_list_item_get_child(item);
    gtk_inscription_set_text(GTK_INSCRIPTION(insc), proc->protocols);
}

static void bind_exe_path_cb(GtkSignalListItemFactory *factory, GtkListItem *item) {
    (void)factory;
    PIDNLProcess *proc = PIDNL_PROCESS(gtk_list_item_get_item(item));
    GtkWidget *insc = gtk_list_item_get_child(item);
    gtk_inscription_set_text(GTK_INSCRIPTION(insc), proc->exe_path);
}

static void bind_upload_limit_cb(GtkSignalListItemFactory *factory, GtkListItem *item) {
    (void)factory;
    PIDNLProcess *proc = PIDNL_PROCESS(gtk_list_item_get_item(item));
    GtkWidget *entry = gtk_list_item_get_child(item);
    g_object_set_data(G_OBJECT(entry), "pid", GINT_TO_POINTER(proc->pid));
    set_entry_to_value(GTK_EDITABLE(entry), proc->upload_kbps);
}

static void bind_download_limit_cb(GtkSignalListItemFactory *factory, GtkListItem *item) {
    (void)factory;
    PIDNLProcess *proc = PIDNL_PROCESS(gtk_list_item_get_item(item));
    GtkWidget *entry = gtk_list_item_get_child(item);
    g_object_set_data(G_OBJECT(entry), "pid", GINT_TO_POINTER(proc->pid));
    set_entry_to_value(GTK_EDITABLE(entry), proc->download_kbps);
}

static gint compare_name(gconstpointer a, gconstpointer b, gpointer user_data) {
    (void)user_data;
    const PIDNLProcess *pa = a;
    const PIDNLProcess *pb = b;
    return g_utf8_collate(pa->name ? pa->name : "", pb->name ? pb->name : "");
}

static gint compare_pid(gconstpointer a, gconstpointer b, gpointer user_data) {
    (void)user_data;
    const PIDNLProcess *pa = a;
    const PIDNLProcess *pb = b;
    return (pa->pid > pb->pid) - (pa->pid < pb->pid);
}

static gint compare_connections(gconstpointer a, gconstpointer b, gpointer user_data) {
    (void)user_data;
    const PIDNLProcess *pa = a;
    const PIDNLProcess *pb = b;
    return (pa->connections > pb->connections) - (pa->connections < pb->connections);
}

static GtkColumnViewColumn *make_column(
    const gchar *title, GCallback setup_cb, GCallback bind_cb, gint min_chars, GtkSorter *sorter
) {
    GtkListItemFactory *factory = gtk_signal_list_item_factory_new();
    g_signal_connect(factory, "setup", setup_cb, GINT_TO_POINTER(min_chars));
    g_signal_connect(factory, "bind", bind_cb, NULL);

    GtkColumnViewColumn *col = gtk_column_view_column_new(title, factory);
    gtk_column_view_column_set_resizable(col, TRUE);
    if (sorter) {
        gtk_column_view_column_set_sorter(col, sorter);
        g_object_unref(sorter);
    }
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
    guint32 upload_kbps,
    guint32 download_kbps
) {
    const char *protocols;
    if (has_tcp && has_udp) {
        protocols = "TCP/UDP";
    } else if (has_tcp) {
        protocols = "TCP";
    } else if (has_udp) {
        protocols = "UDP";
    } else {
        protocols = "-";
    }

    g_autoptr(GIcon) icon = lookup_icon(exe_path, name, pid);
    g_autoptr(PIDNLProcess) proc = pidnl_process_new(
        name, pid, connections, protocols, exe_path, icon, upload_kbps, download_kbps
    );
    g_list_store_append(store, G_OBJECT(proc));
}

static void clear_store(GListStore *store) {
    g_list_store_remove_all(store);
}

static void populate_store_from_raw(GListStore *store, const gchar *data) {
    clear_store(store);

    gchar **lines = g_strsplit(data, "\n", -1);
    if (!lines[0] || !*lines[0]) {
        g_strfreev(lines);
        return;
    }

    gchar *endptr = NULL;
    gint64 count = g_ascii_strtoll(lines[0], &endptr, 10);
    if (endptr == lines[0] || *endptr != '\0' || count <= 0 || count > G_MAXINT) {
        g_strfreev(lines);
        return;
    }

    int idx = 1;
    for (int i = 0; i < count && lines[idx] && lines[idx + 1]; i++) {
        int pid, connections, has_tcp, has_udp;
        unsigned int upload, download;
        char name[256] = {0};
        if (sscanf(
                lines[idx],
                "%d %d %d %d %u %u %255[^\n]",
                &pid,
                &connections,
                &has_tcp,
                &has_udp,
                &upload,
                &download,
                name
            ) == 7) {
            append_process_to_store(
                store, name, pid, connections, has_tcp, has_udp, lines[idx + 1], upload, download
            );
        }
        idx += 2;
    }

    g_strfreev(lines);
}

void pidnl_processes_view_set_backend(GtkWidget *view, PIDNLBackend *backend) {
    g_object_set_data(G_OBJECT(view), "backend", backend);
}

GtkWidget *pidnl_processes_view_new(const gchar *raw_data) {
    GListStore *store = g_list_store_new(PIDNL_TYPE_PROCESS);

    GtkSortListModel *sort_model = gtk_sort_list_model_new(G_LIST_MODEL(store), NULL);
    g_autoptr(GtkNoSelection) selection = gtk_no_selection_new(G_LIST_MODEL(sort_model));
    GtkWidget *column_view = gtk_column_view_new(GTK_SELECTION_MODEL(selection));

    gtk_column_view_append_column(
        GTK_COLUMN_VIEW(column_view),
        make_column(
            "Name",
            G_CALLBACK(setup_name_cb),
            G_CALLBACK(bind_name_cb),
            0,
            GTK_SORTER(gtk_custom_sorter_new(compare_name, NULL, NULL))
        )
    );
    gtk_column_view_append_column(
        GTK_COLUMN_VIEW(column_view),
        make_column(
            "PID",
            G_CALLBACK(setup_column_cb),
            G_CALLBACK(bind_pid_cb),
            10,
            GTK_SORTER(gtk_custom_sorter_new(compare_pid, NULL, NULL))
        )
    );
    gtk_column_view_append_column(
        GTK_COLUMN_VIEW(column_view),
        make_column(
            "Connections",
            G_CALLBACK(setup_column_cb),
            G_CALLBACK(bind_connections_cb),
            12,
            GTK_SORTER(gtk_custom_sorter_new(compare_connections, NULL, NULL))
        )
    );
    gtk_column_view_append_column(
        GTK_COLUMN_VIEW(column_view),
        make_column(
            "Protocols", G_CALLBACK(setup_column_cb), G_CALLBACK(bind_protocols_cb), 10, NULL
        )
    );
    gtk_column_view_append_column(
        GTK_COLUMN_VIEW(column_view),
        make_column(
            "Upload Limit (kbps)",
            G_CALLBACK(setup_upload_limit_cb),
            G_CALLBACK(bind_upload_limit_cb),
            10,
            NULL
        )
    );
    gtk_column_view_append_column(
        GTK_COLUMN_VIEW(column_view),
        make_column(
            "Download Limit (kbps)",
            G_CALLBACK(setup_download_limit_cb),
            G_CALLBACK(bind_download_limit_cb),
            10,
            NULL
        )
    );
    gtk_column_view_append_column(
        GTK_COLUMN_VIEW(column_view),
        make_column(
            "Command Line", G_CALLBACK(setup_column_cb), G_CALLBACK(bind_exe_path_cb), 30, NULL
        )
    );

    gtk_sort_list_model_set_sorter(
        sort_model, gtk_column_view_get_sorter(GTK_COLUMN_VIEW(column_view))
    );

    GtkGesture *click = gtk_gesture_click_new();
    gtk_widget_add_controller(column_view, GTK_EVENT_CONTROLLER(click));
    g_signal_connect(click, "pressed", G_CALLBACK(on_column_view_pressed), column_view);

    GtkWidget *scrolled = gtk_scrolled_window_new();
    gtk_scrolled_window_set_policy(
        GTK_SCROLLED_WINDOW(scrolled), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC
    );
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled), column_view);
    gtk_widget_set_vexpand(scrolled, TRUE);
    gtk_widget_set_hexpand(scrolled, TRUE);

    g_object_set_data_full(G_OBJECT(scrolled), "store", store, g_object_unref);
    g_object_set_data_full(G_OBJECT(scrolled), "raw-data", g_strdup(raw_data), g_free);
    populate_store_from_raw(store, raw_data);

    return scrolled;
}

void pidnl_processes_view_refresh(GtkWidget *view, const gchar *raw_data) {
    GListStore *store = get_store_from_view(view);
    populate_store_from_raw(store, raw_data);
}
