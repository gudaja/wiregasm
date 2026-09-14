#ifndef WIREGASM_COMMON_H
#define WIREGASM_COMMON_H

#include "wiregasm.h"
#include <common/frame_tvbuff.h>
#include <common/io_graph_item.h>
#include <common/summary.h>
#include <epan/addr_resolv.h>
#include <epan/color_filters.h>
#include <epan/column.h>
#include <epan/conversation_table.h>
#include <epan/epan.h>
#include <epan/epan_dissect.h>
#include <epan/exceptions.h>
#include <epan/expert.h>
#include <epan/export_object.h>
#include <epan/follow.h>
#include <epan/maxmind_db.h>
#include <epan/print.h>
#include <epan/secrets.h>
#include <epan/tap.h>
#include <epan/timestamp.h>
#include <epan/tvbuff.h>
#include <glib.h>
#include <wireshark/cfile.h>
#include <wiretap/wtap.h>
#include <wsutil/filesystem.h>
#include <wsutil/str_util.h>
#include <wsutil/strtoi.h>

// callbacks, defined in lib.js (added through --js-library)

enum StatusType {
  WARN = 0,
  INFO = 1,
  ERROR = 2
};

extern "C" {
extern void on_status(enum StatusType, const char *);
}

struct wg_filter_item {
  guint8 *filtered; /* can be NULL if all frames are matching for given filter. */
  guint passed;
  guint computed_count; /* number of frames the bitmap was computed for */
};

enum dissect_request_status {
  DISSECT_REQUEST_SUCCESS,
  DISSECT_REQUEST_NO_SUCH_FRAME,
  DISSECT_REQUEST_READ_ERROR
};

typedef enum {
  CF_OK,   /**< operation succeeded */
  CF_ERROR /**< operation got an error (function may provide err with details) */
} cf_status_t;

typedef void (*wg_dissect_func_t)(capture_file *cfile, epan_dissect_t *edt, proto_tree *tree, struct epan_column_info *cinfo, const GSList *data_src, void *data);

#define WG_DISSECT_FLAG_NULL 0x00u
#define WG_DISSECT_FLAG_BYTES 0x01u
#define WG_DISSECT_FLAG_COLUMNS 0x02u
#define WG_DISSECT_FLAG_PROTO_TREE 0x04u
#define WG_DISSECT_FLAG_COLOR 0x08u

/* return codes of wg_continue_tail() */
#define WG_TAIL_OK 0
#define WG_TAIL_ERROR 1
#define WG_TAIL_SHORT_READ 2 /* terminal: a partial block was appended */

void wg_session_filter_free(gpointer data);
int wg_load_cap_file(capture_file *cfile, summary_tally *summary, bool keep_open);
int wg_session_process_load(capture_file *cfile, const char *path, summary_tally *summary, char **err_ret, bool keep_open);
/* Must not be called after wg_finish_tail(), which closes the sequential
   handle; both report WG_TAIL_ERROR through cf->state in that case. */
int wg_continue_tail(capture_file *cfile, guint32 *new_frames, char **err_ret);
int wg_finish_tail(capture_file *cfile);
FramesResponse wg_process_frames(capture_file *cfile, GHashTable *filter_table, const char *filter, guint32 skip, guint32 limit, char **err_ret);
Frame wg_process_frame(capture_file *cfile, guint32 framenum, char **err_ret);
Follow wg_process_follow(capture_file *cfile, const char *follow, const char *filter, char **err_ret);
bool wg_session_eo_retap_listener(capture_file *cfile, const char *tap_type, char **err_ret);
DownloadResponse wg_session_process_download(capture_file *cfile, const char *token);
TapResponse wg_session_process_tap(capture_file *cfile, MapInput taps);
IoGraphResult wg_session_process_iograph(capture_file *cfile, MapInput input);
vector<CompleteField> wg_session_process_complete(const char *field);
void cf_close(capture_file *cf);

#endif
