void gui_fatal(const char *fmt, ...) __attribute__((noreturn));
void gui_nonfatal(const char *fmt, ...);
void qfile_gui_fatal(const char *fmt, va_list args) __attribute__((noreturn));
