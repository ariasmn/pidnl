#ifndef PROCESSES_H
#define PROCESSES_H

#include <adwaita.h>

#define STRAIT_TYPE_PROCESS (strait_process_get_type())
G_DECLARE_FINAL_TYPE(StraitProcess, strait_process, STRAIT, PROCESS, GObject)

G_BEGIN_DECLS

GtkWidget *strait_processes_view_new(const gchar *raw_data);
void strait_processes_view_refresh(GtkWidget *view);
void strait_processes_view_start_refresh(GtkWidget *view, guint interval_sec);
void strait_processes_view_stop_refresh(GtkWidget *view);

G_END_DECLS

#endif
