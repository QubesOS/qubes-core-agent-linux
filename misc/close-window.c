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

int main(int argc, char **argv) {
	int i;
	Display *d;

	d = XOpenDisplay(NULL);
	if (!d)
		exit(1);
	for (i=1; i<argc; i++) {
		close_window(d, strtoul(argv[i], NULL, 0));
	}
	XSync(d, False);
	XCloseDisplay(d);
	return 0;
}
