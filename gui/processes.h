#ifndef PROCESSES_H
#define PROCESSES_H

#include <adwaita.h>

#include "backend.h"

#define STRAIT_TYPE_PROCESS (strait_process_get_type())
G_DECLARE_FINAL_TYPE(StraitProcess, strait_process, STRAIT, PROCESS, GObject)

G_BEGIN_DECLS

GtkWidget *strait_processes_view_new(const gchar *raw_data);
void strait_processes_view_set_backend(GtkWidget *view, StraitBackend *backend);
void strait_processes_view_refresh(GtkWidget *view, const gchar *raw_data);

G_END_DECLS

#endif
