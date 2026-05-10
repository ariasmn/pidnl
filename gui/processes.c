#include "processes.h"
#include "discovery.h"

#include <string.h>
#include <stdlib.h>

#define STRAIT_TYPE_PROCESS (strait_process_get_type())
G_DECLARE_FINAL_TYPE(StraitProcess, strait_process, STRAIT, PROCESS, GObject)

struct _StraitProcess {
    GObject parent_instance;
    gchar  *name;
    gint    pid;
    gint    connections;
    gchar  *protocols;
    gchar  *exe_path;
};

G_DEFINE_TYPE(StraitProcess, strait_process, G_TYPE_OBJECT)

static void
strait_process_finalize(GObject *object)
{
    StraitProcess *self = STRAIT_PROCESS(object);
    g_free(self->name);
    g_free(self->protocols);
    g_free(self->exe_path);
    G_OBJECT_CLASS(strait_process_parent_class)->finalize(object);
}

static void
strait_process_class_init(StraitProcessClass *klass)
{
    G_OBJECT_CLASS(klass)->finalize = strait_process_finalize;
}

static void
strait_process_init(StraitProcess *self)
{
    (void)self;
}

static StraitProcess *
strait_process_new(const gchar *name, gint pid, gint connections,
                   const gchar *protocols, const gchar *exe_path)
{
    StraitProcess *p = g_object_new(STRAIT_TYPE_PROCESS, NULL);
    p->name        = g_strdup(name);
    p->pid         = pid;
    p->connections = connections;
    p->protocols   = g_strdup(protocols);
    p->exe_path    = g_strdup(exe_path);
    return p;
}

/* ------------------------------------------------------------------ */
/* Factories & bindings                                               */
/* ------------------------------------------------------------------ */

static void
setup_label_left(GtkSignalListItemFactory *factory, GObject *object)
{
    (void)factory;
    GtkListItem *item = GTK_LIST_ITEM(object);
    GtkWidget   *label = gtk_label_new(NULL);
    gtk_label_set_xalign(GTK_LABEL(label), 0.0);
    gtk_widget_set_halign(label, GTK_ALIGN_START);
    gtk_label_set_ellipsize(GTK_LABEL(label), PANGO_ELLIPSIZE_END);
    gtk_widget_set_hexpand(label, TRUE);
    gtk_list_item_set_child(item, label);
}

static void
setup_label_right(GtkSignalListItemFactory *factory, GObject *object)
{
    (void)factory;
    GtkListItem *item = GTK_LIST_ITEM(object);
    GtkWidget   *label = gtk_label_new(NULL);
    gtk_label_set_xalign(GTK_LABEL(label), 1.0);
    gtk_widget_set_halign(label, GTK_ALIGN_END);
    gtk_label_set_ellipsize(GTK_LABEL(label), PANGO_ELLIPSIZE_END);
    gtk_widget_set_hexpand(label, TRUE);
    gtk_list_item_set_child(item, label);
}

static void
setup_command_line(GtkSignalListItemFactory *factory, GObject *object)
{
    (void)factory;
    GtkListItem *item = GTK_LIST_ITEM(object);
    GtkWidget   *label = gtk_label_new(NULL);
    gtk_label_set_xalign(GTK_LABEL(label), 0.0);
    gtk_widget_set_halign(label, GTK_ALIGN_START);
    gtk_label_set_ellipsize(GTK_LABEL(label), PANGO_ELLIPSIZE_END);
    gtk_widget_set_hexpand(label, TRUE);
    gtk_widget_set_size_request(label, 200, -1);
    gtk_list_item_set_child(item, label);
}

static void
bind_name(GtkSignalListItemFactory *factory, GObject *object)
{
    (void)factory;
    GtkListItem   *item = GTK_LIST_ITEM(object);
    StraitProcess *proc = STRAIT_PROCESS(gtk_list_item_get_item(item));
    GtkWidget     *label = gtk_list_item_get_child(item);
    gtk_label_set_text(GTK_LABEL(label), proc->name);
}

static void
bind_pid(GtkSignalListItemFactory *factory, GObject *object)
{
    (void)factory;
    GtkListItem   *item = GTK_LIST_ITEM(object);
    StraitProcess *proc = STRAIT_PROCESS(gtk_list_item_get_item(item));
    GtkWidget     *label = gtk_list_item_get_child(item);
    gchar         *text = g_strdup_printf("%d", proc->pid);
    gtk_label_set_text(GTK_LABEL(label), text);
    g_free(text);
}

static void
bind_connections(GtkSignalListItemFactory *factory, GObject *object)
{
    (void)factory;
    GtkListItem   *item = GTK_LIST_ITEM(object);
    StraitProcess *proc = STRAIT_PROCESS(gtk_list_item_get_item(item));
    GtkWidget     *label = gtk_list_item_get_child(item);
    gchar         *text = g_strdup_printf("%d", proc->connections);
    gtk_label_set_text(GTK_LABEL(label), text);
    g_free(text);
}

static void
bind_protocols(GtkSignalListItemFactory *factory, GObject *object)
{
    (void)factory;
    GtkListItem   *item = GTK_LIST_ITEM(object);
    StraitProcess *proc = STRAIT_PROCESS(gtk_list_item_get_item(item));
    GtkWidget     *label = gtk_list_item_get_child(item);
    gtk_label_set_text(GTK_LABEL(label), proc->protocols);
}

static void
bind_exe_path(GtkSignalListItemFactory *factory, GObject *object)
{
    (void)factory;
    GtkListItem   *item = GTK_LIST_ITEM(object);
    StraitProcess *proc = STRAIT_PROCESS(gtk_list_item_get_item(item));
    GtkWidget     *label = gtk_list_item_get_child(item);
    gtk_label_set_text(GTK_LABEL(label), proc->exe_path);
}

/* ------------------------------------------------------------------ */
/* Column helper                                                      */
/* ------------------------------------------------------------------ */

static GtkColumnViewColumn *
make_column(const gchar *title,
            GCallback    setup_cb,
            GCallback    bind_cb,
            gboolean     expand,
            gboolean     resizable)
{
    GtkListItemFactory *factory = gtk_signal_list_item_factory_new();
    g_signal_connect(factory, "setup", setup_cb, NULL);
    g_signal_connect(factory, "bind",  bind_cb,  NULL);

    GtkColumnViewColumn *col = gtk_column_view_column_new(title, factory);
    gtk_column_view_column_set_resizable(col, resizable);
    gtk_column_view_column_set_expand(col, expand);
    return col;
}

/* ------------------------------------------------------------------ */
/* Data loading                                                       */
/* ------------------------------------------------------------------ */

static int
compare_by_pid(const void *a, const void *b)
{
    const process_info *pa = a;
    const process_info *pb = b;
    return (pa->pid > pb->pid) - (pa->pid < pb->pid);
}

static void
clear_store(GListStore *store)
{
    guint n = g_list_model_get_n_items(G_LIST_MODEL(store));
    while (n > 0) {
        g_list_store_remove(store, --n);
    }
}

static GListStore *
get_store_from_view(GtkWidget *view)
{
    return G_LIST_STORE(g_object_get_data(G_OBJECT(view), "store"));
}

static void
populate_store(GListStore *store)
{
    process_list *list = NULL;
    discovery_code code = get_network_processes(&list);

    clear_store(store);

    if (code != DISCOVERY_OK) {
        g_warning("Failed to get network processes: %s", discovery_code_string(code));
        return;
    }

    qsort(list->processes, list->count, sizeof(process_info), compare_by_pid);

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

        StraitProcess *proc = strait_process_new(
            p->process_name, (gint)p->pid, p->num_connections,
            protocols, p->exe_path);
        g_list_store_append(store, G_OBJECT(proc));
        g_object_unref(proc);
    }

    destroy_process_list(list);
}

static gboolean
on_refresh_timeout(gpointer user_data)
{
    GtkWidget *view = GTK_WIDGET(user_data);
    populate_store(get_store_from_view(view));
    return G_SOURCE_CONTINUE;
}

/* ------------------------------------------------------------------ */
/* Public API                                                         */
/* ------------------------------------------------------------------ */

GtkWidget *
strait_processes_view_new(void)
{
    GListStore *store = g_list_store_new(STRAIT_TYPE_PROCESS);

    GtkNoSelection *selection = gtk_no_selection_new(G_LIST_MODEL(store));
    GtkWidget *column_view = gtk_column_view_new(GTK_SELECTION_MODEL(selection));
    g_object_unref(selection);

    gtk_column_view_append_column(GTK_COLUMN_VIEW(column_view),
        make_column("Name", G_CALLBACK(setup_label_left), G_CALLBACK(bind_name), TRUE, TRUE));
    gtk_column_view_append_column(GTK_COLUMN_VIEW(column_view),
        make_column("PID", G_CALLBACK(setup_label_right), G_CALLBACK(bind_pid), FALSE, TRUE));
    gtk_column_view_append_column(GTK_COLUMN_VIEW(column_view),
        make_column("Connections", G_CALLBACK(setup_label_right), G_CALLBACK(bind_connections), FALSE, TRUE));
    gtk_column_view_append_column(GTK_COLUMN_VIEW(column_view),
        make_column("Protocols", G_CALLBACK(setup_label_left), G_CALLBACK(bind_protocols), FALSE, TRUE));
    gtk_column_view_append_column(GTK_COLUMN_VIEW(column_view),
        make_column("Command Line", G_CALLBACK(setup_command_line), G_CALLBACK(bind_exe_path), TRUE, TRUE));

    GtkWidget *scrolled = gtk_scrolled_window_new();
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled),
                                   GTK_POLICY_AUTOMATIC,
                                   GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled), column_view);
    gtk_widget_set_vexpand(scrolled, TRUE);
    gtk_widget_set_hexpand(scrolled, TRUE);

    g_object_set_data_full(G_OBJECT(scrolled), "store", store, g_object_unref);

    populate_store(store);

    return scrolled;
}

void
strait_processes_view_refresh(GtkWidget *view)
{
    populate_store(get_store_from_view(view));
}

void
strait_processes_view_start_refresh(GtkWidget *view, guint interval_sec)
{
    strait_processes_view_stop_refresh(view);

    guint id = g_timeout_add_seconds(interval_sec, on_refresh_timeout, view);
    g_object_set_data(G_OBJECT(view), "timeout-id", GUINT_TO_POINTER(id));
}

void
strait_processes_view_stop_refresh(GtkWidget *view)
{
    guint id = GPOINTER_TO_UINT(g_object_get_data(G_OBJECT(view), "timeout-id"));
    if (id != 0) {
        g_source_remove(id);
        g_object_set_data(G_OBJECT(view), "timeout-id", GUINT_TO_POINTER(0));
    }
}
