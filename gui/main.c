#include <adwaita.h>
#include <glib.h>

#include "processes.h"

static void on_refresh_clicked(GtkButton *button, gpointer user_data) {
    (void)button;
    GtkWidget *view = GTK_WIDGET(user_data);
    strait_processes_view_refresh(view);
}

static gboolean on_close_request(GtkWindow *window, gpointer user_data) {
    GtkApplication *app = GTK_APPLICATION(user_data);
    GtkWidget *view = GTK_WIDGET(g_object_get_data(G_OBJECT(window), "processes-view"));
    strait_processes_view_stop_refresh(view);
    g_application_quit(G_APPLICATION(app));
    return TRUE;
}

static void on_activate(GtkApplication *app, gpointer user_data) {
    (void)user_data;

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

    GtkWidget *processes_view = strait_processes_view_new();
    g_object_set_data(G_OBJECT(window), "processes-view", processes_view);
    g_signal_connect(refresh_button, "clicked", G_CALLBACK(on_refresh_clicked), processes_view);
    adw_header_bar_pack_end(header_bar, refresh_button);

    adw_toolbar_view_set_content(ADW_TOOLBAR_VIEW(toolbar_view), processes_view);

    g_signal_connect(window, "close-request", G_CALLBACK(on_close_request), app);

    gtk_window_present(GTK_WINDOW(window));

    strait_processes_view_start_refresh(processes_view, 5);
}

int main(int argc, char **argv) {
    AdwApplication *app = adw_application_new("com.example.strait", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(on_activate), NULL);
    int status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);
    return status;
}
