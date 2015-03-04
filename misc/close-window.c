#include <X11/Xutil.h>
#include <X11/Xlib.h>
#include <string.h>
#include <stdlib.h>

int close_window(Display *d, XID window) {
	XClientMessageEvent ev;
	memset(&ev, 0, sizeof(ev));
	ev.type = ClientMessage;
	ev.display = d;
	ev.window = window;
	ev.format = 32;
	ev.message_type = XInternAtom(d, "WM_PROTOCOLS", False);
	ev.data.l[0] = XInternAtom(d, "WM_DELETE_WINDOW", False);;
	return XSendEvent(ev.display, ev.window, True, 0, (XEvent *) & ev);
}

int is_window_visible(Display *d, XID window) {
    XWindowAttributes xwa;

    if (!XGetWindowAttributes(d, window, &xwa))
        return 0;
    return xwa.map_state == IsViewable;
}

int main(int argc, char **argv) {
	int i;
	Display *d;
	XID w;

	d = XOpenDisplay(NULL);
	if (!d)
		exit(1);
	for (i=1; i<argc; i++) {
        w = strtoul(argv[i], NULL, 0);
        if (is_window_visible(d, w))
                close_window(d, w);
	}
	XSync(d, False);
	XCloseDisplay(d);
	return 0;
}
