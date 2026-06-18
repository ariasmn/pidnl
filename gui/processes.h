#ifndef PROCESSES_H
#define PROCESSES_H

#include <adwaita.h>

#include "backend.h"

#define PIDNL_TYPE_PROCESS (pidnl_process_get_type())
G_DECLARE_FINAL_TYPE(PIDNLProcess, pidnl_process, PIDNL, PROCESS, GObject)

G_BEGIN_DECLS

GtkWidget *pidnl_processes_view_new(const gchar *raw_data);
void pidnl_processes_view_set_backend(GtkWidget *view, PIDNLBackend *backend);
void pidnl_processes_view_refresh(GtkWidget *view, const gchar *raw_data);

G_END_DECLS

#endif
