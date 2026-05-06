#include <adwaita.h>
#include <stdlib.h>

static void on_activate(GtkApplication *app, gpointer user_data) {
    (void)user_data;

    GtkWidget *window = adw_application_window_new(GTK_APPLICATION(app));
    gtk_window_set_title(GTK_WINDOW(window), "Strait");
    gtk_window_set_default_size(GTK_WINDOW(window), 600, 400);

    GtkWidget *toolbar_view = adw_toolbar_view_new();
    adw_application_window_set_content(ADW_APPLICATION_WINDOW(window), toolbar_view);

    AdwHeaderBar *header_bar = ADW_HEADER_BAR(adw_header_bar_new());
    adw_toolbar_view_add_top_bar(ADW_TOOLBAR_VIEW(toolbar_view), GTK_WIDGET(header_bar));

    AdwStatusPage *status_page = ADW_STATUS_PAGE(adw_status_page_new());
    adw_status_page_set_title(status_page, "Hello, World!");
    adw_status_page_set_description(status_page, "Welcome to Strait GUI.");
    adw_toolbar_view_set_content(ADW_TOOLBAR_VIEW(toolbar_view), GTK_WIDGET(status_page));

    gtk_window_present(GTK_WINDOW(window));
}

int main(int argc, char **argv) {
    /* Force glib to use standard malloc instead of its slab allocator.
     * This eliminates ASan false positives from GSlice. Must be set
     * before any glib allocations happen. */
    (void)setenv("G_SLICE", "always-malloc", 1);

    AdwApplication *app = adw_application_new("com.example.strait", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(on_activate), NULL);
    int status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);
    return status;
}
