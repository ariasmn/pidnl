#ifndef PROCESSES_H
#define PROCESSES_H

#include <adwaita.h>

G_BEGIN_DECLS

GtkWidget *strait_processes_view_new(void);
void strait_processes_view_refresh(GtkWidget *view);
void strait_processes_view_start_refresh(GtkWidget *view, guint interval_sec);
void strait_processes_view_stop_refresh(GtkWidget *view);

G_END_DECLS

#endif
