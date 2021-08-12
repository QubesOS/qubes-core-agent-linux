#!/usr/bin/env python3
# vim: fileencoding=utf-8
#
# The Qubes OS Project, https://www.qubes-os.org/
#
# Copyright (C) 2021
#                   David Hobach <tripleh@hackingthe.net>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

import os
import signal as ossignal
import sys
import logging
import re
import time
import subprocess
import pwd
from collections import namedtuple
import argparse
import traceback
from threading import Thread
from queue import Queue
import dbus
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib
import qubesdb

def get_logger(name, verbose=False):
    log = logging.getLogger(name)
    log.addHandler(logging.StreamHandler(sys.stderr))
    if verbose:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)
    return log

def launch_private_dbus(launch_script):
    """ Launch a private dbus instance. """
    out = subprocess.check_output(["sudo", launch_script]).decode()
    for line in out.strip().split("\n"):
        key, _, value = line.partition("=")
        if key == "DBUS_SESSION_BUS_ADDRESS":
            addr = value
        elif key == "DBUS_SESSION_BUS_PID":
            pid = int(value)
    assert addr
    assert pid
    return addr, pid

def remove_newlines(txt, replace=" "):
    return txt.replace("\n", replace)

Notification = namedtuple("Notification", ("app_name", "notification_id", "app_icon",
                                           "summary", "body", "actions", "hints",
                                           "expire_timeout"))

class WorkerDiedException(Exception):
    pass

class IdleTimeoutException(Exception):
    def __init__(self):
        super().__init__("Idle timeout. Exiting...")

class QrexecWorker(Thread):
    """ Processes incoming qrexec signals synchronously in the order that they come. """

    def __init__(self, queue, notification_vm, verbose=False):
        self.log = get_logger("qubes-notification-forwarder QrexecWorker", verbose=verbose)
        self.queue = queue
        self.notification_vm = notification_vm
        self.init_proc()
        self.deaths = 0
        super().__init__(daemon=True)

    def run(self):
        while True:
            signal = self.queue.get()
            self.process(signal)
            self.queue.task_done()

    def init_proc(self):
        self.proc = subprocess.Popen(["/usr/lib/qubes/qrexec-client-vm", self.notification_vm,
                                      "qubes.DesktopNotify"], stdin=subprocess.PIPE,
                                     universal_newlines=True)

    def qrexec(self, run_str):
        if self.proc.poll():
            if self.deaths > 2:
                self.log.error("Qrexec died too often. Giving up...")
                sys.exit(5)
            self.log.warning("Qrexec connection has died. Restarting...")
            self.init_proc()
            self.deaths += 1
        else:
            self.deaths = 0

        #remove begin & end tags, if they happen to be in the string
        rstr = re.sub(r"(?m)^</?qrexec>$", "", run_str)

        rstr = "\n".join(["<qrexec>", rstr, "</qrexec>\n"])
        self.log.debug(rstr)
        self.proc.stdin.write(rstr)
        self.proc.stdin.flush()

    def process(self, signal):
        if signal["command"] == "close":
            self.qrexec("\n".join([
                signal["command"],
                str(signal["notification_id"]),
            ]))
        elif signal["command"] == "notify":
            notification = signal["notification"]
            self.qrexec("\n".join([
                signal["command"],
                str(signal["notification_id"]),
                str(notification.expire_timeout),
                remove_newlines(notification.app_name),
                self.get_icon(notification),
                remove_newlines(notification.summary),
                notification.body, #last as it may have newlines
            ]))
        else:
            self.log.error("Unexpected command sent to QrexecWorker.")

    def test_icon(self, icon):
        if not isinstance(icon, str):
            return ""

        #only forward icons that the receiver might be able to use
        #(regexes copied from qubes.DesktopNotify code)
        if re.match(r"^file://(/usr/share/[^\0]+\.(?:png|svg|gif))$", icon) \
        and not "/tmp/" in icon:
            return icon
        if re.match(r"^([a-z\-]{0,30})$", icon):
            return icon

        return ""

    def get_icon(self, notification):
        #standard says: image-path has preference
        icon = self.test_icon(notification.hints.get("image-path"))
        if icon:
            return icon
        return self.test_icon(notification.app_icon)

class NotificationForwarder(dbus.service.Object):
    """
    A proxy of the Desktop Notification Specification [1] for Qubes OS.

    This proxy can be run inside a VM to intercept and forward locally generated
    notifications to other VMs. It may also decide to let the locally running
    desktop notification server [1] handle incoming notifications depending on
    e.g. the capabilities required by the requesting application.

    To keep it simple and more secure, there's currently no channel back from the
    receiving VM to this proxy (otherwise the receiving VM might use that to compromise
    us).
    In particular if the user closes or clicks a button on a forwarded notification, the
    originating application won't be informed. Therefore the current implementation does
    not forward notifications with buttons, but lets the locally running desktop
    notification server handle them.

    `dbus-monitor "interface=org.freedesktop.Notifications"` is useful for debugging.

    The proxy assumes that the target VM to forward notifications to is named at the
    QubesDB path `/desktop-notification-target`. Otherwise it will exit and let the
    local desktop notification server handle all notifications.

    References:
        [1] https://developer.gnome.org/notification-spec/
        [2] https://dbus.freedesktop.org/doc/dbus-python/
        [3] https://lazka.github.io/pgi-docs/
    """

    def __init__(self, notification_vm, private_dbus_address, verbose=False, local_mode=False, force_mode=False, exit_idle=False):
        self._id = 0 #: current server notification ID
        self.notification_vm = notification_vm
        self.local_mode = local_mode
        self.force_mode = force_mode
        self.exit_idle = exit_idle
        self.default_expiry = 10000 #: time in ms after which a notification is considered expired (if not specified by the user)
        self.busy_until = -1 #: unix timestamp until which the forwarder is busy
        self.log = get_logger("qubes-notification-forwarder", verbose)

        self.server2local_id = dict() #: server notification ID --> local client ID
        self.local2server_id = dict() #: local client ID --> server notification ID

        dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

        self.private_bus = dbus.bus.BusConnection(private_dbus_address)

        #signal handling
        bn = "org.freedesktop.Notifications"
        path = "/org/freedesktop/Notifications"
        self.private_bus.add_signal_receiver(self.on_local_closed, signal_name="NotificationClosed", bus_name=bn, path=path)
        self.private_bus.add_signal_receiver(self.on_local_action, signal_name="ActionInvoked", bus_name=bn, path=path)

        self.capabilities = self.iface.GetCapabilities()

        self.qrexec_queue = Queue(100)
        self.qrexec_worker = QrexecWorker(self.qrexec_queue, notification_vm, verbose=verbose)
        self.qrexec_worker.start()

        bus_name = dbus.service.BusName(bn, bus=dbus.SessionBus())

        if self.exit_idle:
            self.mark_busy(30000)
            GLib.timeout_add(1000, self.exit_if_idle)
        super().__init__(bus_name, path)

    @property
    def iface(self):
        """ Interface for local notification handling. """
        # Storing the proxy or interface doesn't seem to be wise: After a while (30s-10min) one runs into a
        # DBus.Error.ServiceUnknown (i.e. some timeout) - at least on debian 10. Maybe a python-dbus bug?
        # As a workaround we re-request the proxy all of the time.
        #
        # Minimal code to reproduce the issue:
        #
	# import dbus
	# import time
	#
	# bus = dbus.SessionBus()
	# proxy = bus.get_object("org.freedesktop.Notifications", "/org/freedesktop/Notifications")
	# iface = dbus.Interface(proxy, "org.freedesktop.Notifications")
	#
	# while True:
	#   print("Notifying...")
	#   iface.Notify('foo', 0, '', 'summary', 'body', [], {}, 10000)
	#   time.sleep(300)
        proxy = self.private_bus.get_object("org.freedesktop.Notifications", "/org/freedesktop/Notifications")
        return dbus.Interface(proxy, "org.freedesktop.Notifications")

    def run(self):
        GLib.MainLoop().run()

    def schedule(self, worker, queue, content):
        if worker.is_alive():
            queue.put(content, timeout=5)
        else:
            raise WorkerDiedException(f"{worker.__class__.__name__} dead. Exiting...")

    def mark_busy(self, timeout):
        ''' Mark us as busy for the given time in ms. '''
        if self.exit_idle:
            t = timeout
            if not t or t < 1:
                t = self.default_expiry
            now = int(time.time())
            t = int(t / 1000) +1
            busy_until = now + t
            if self.busy_until < busy_until:
                self.busy_until = busy_until

    def exit_if_idle(self):
        now = int(time.time())
        self.log.debug(f"Checking idle status at {now}. We're busy until {self.busy_until}.")
        if now > self.busy_until:
            raise IdleTimeoutException()
        return True

    def schedule_qrexec(self, content):
        return self.schedule(self.qrexec_worker, self.qrexec_queue, content)

    @dbus.service.method("org.freedesktop.Notifications", in_signature="",
                         out_signature="as")
    def GetCapabilities(self):
        #always handle locally
        self.log.debug("GetCapabilities")
        return self.capabilities

    @dbus.service.method("org.freedesktop.Notifications",
                         in_signature="susssasa{sv}i",
                         out_signature="u")
    def Notify(self, app_name, notification_id, app_icon,
               summary, body, actions, hints, expire_timeout):
        notification = Notification(
            app_name=app_name,
            notification_id=notification_id,
            app_icon=app_icon,
            summary=summary,
            body=body,
            actions=actions,
            hints=hints,
            expire_timeout=expire_timeout,
            )
        self.log.debug("Notify")

        if self.should_forward(notification):
            self.log.debug(f"Forwarding: {notification}")
            server_id = self.forward(notification)
        else:
            self.log.debug(f"Handling locally: {notification}")

            if notification_id == 0:
                #new ID required
                server_id = self.allocate_id()
                local_id = 0
            else:
                #previously used ID
                server_id = notification_id
                local_id = self.server2local_id.get(server_id, 0)

            local_id = self.iface.Notify(app_name, local_id, app_icon, summary,
                                         body, actions, hints, expire_timeout,
                                         signature="susssasa{sv}i")
            self.update_id(server_id, local_id)

        self.mark_busy(expire_timeout)
        return server_id

    def should_forward(self, notification):
        """ Returns true, if the given notification is meant to be forwarded to the remote VM. """
        if self.force_mode:
            return True
        if self.local_mode:
            return False

        # regular mode
        # We cannot handle actions as they require a backchannel which might not be so wise having from
        # a security point of view. So we handle those locally.
        #
        # In the future it might be worth letting the user decide per notification via some config files.
        actions = notification.actions
        if not actions:
            return True
        actions = set(actions)
        actions.discard("default")
        actions.discard("Default")
        if notification.app_name == "Firefox":
            actions.discard("Activate") #this seems to do nothing anyway
        return len(actions) == 0

    def forward(self, notification):
        """ Forward the given notification to the notification VM.
        Not supported:
        - Actions: Such notifications are therefore handled locally.
        - Close signals: Apps are informed about close signals at expiration time regardless of the
                         actual close time of the forwarded notification.
        - Action signals: Apps aren't informed about such signals from forwarded notifications.
        """
        #NOTE: We always allocate an ID and pass it to the VM to make it possible for the VM
        #      to understand our replacing logic: If it has never seen the ID before, it should
        #      simply create a new notification and otherwise replace the previously seen one.
        ret_id = notification.notification_id
        if ret_id == 0:
            ret_id = self.allocate_id()

        self.schedule_qrexec({
            "command": "notify",
            "notification_id": ret_id,
            "notification": notification,
            })

        #schedule close signal
        expire = notification.expire_timeout
        if not expire or expire < 1:
            expire = self.default_expiry
        GLib.timeout_add(expire, lambda: self.NotificationClosed(ret_id, 2) and False)

        return ret_id

    def allocate_id(self):
        """ Allocate a new notification ID. """
        self._id += 1
        if self._id > 2**31:
            self._id = 1
        return self._id

    def update_id(self, server_id, local_id):
        self.server2local_id[server_id] = local_id
        self.local2server_id[local_id] = server_id

    def remove_id(self, server_id):
        local_id = self.server2local_id.get(server_id)
        self.server2local_id.pop(server_id, None)
        if local_id:
            self.local2server_id.pop(local_id, None)

    @dbus.service.method("org.freedesktop.Notifications", in_signature="u",
                         out_signature="")
    def CloseNotification(self, notification_id):
        self.log.debug("CloseNotification")
        local_id = self.server2local_id.get(notification_id)
        if local_id:
            #was handled locally
            self.iface.CloseNotification(local_id, signature="u")
        else:
            #was handled by forwarding
            self.schedule_qrexec({
                "command": "close",
                "notification_id": notification_id,
                })

        #spec requires us to emit the respective signal
        self.NotificationClosed(notification_id, 3)

    @dbus.service.method("org.freedesktop.Notifications", in_signature="",
                         out_signature="ssss")
    def GetServerInformation(self):
        self.log.debug("GetServerInformation")
        return ("qubes-notification-forwarder", "https://www.qubes-os.org/", "0.3", "1.2")

    @dbus.service.signal("org.freedesktop.Notifications", signature="uu")
    def NotificationClosed(self, notification_id, reason):
        self.log.debug("NotificationClosed")

    @dbus.service.signal("org.freedesktop.Notifications", signature="us")
    def ActionInvoked(self, notification_id, action_key):
        self.log.debug("ActionInvoked")

    def on_local_closed(self, *args, **kwargs):
        self.log.debug("on_local_closed")
        try:
            local_id = args[0]
            reason = args[1]
        except IndexError:
            self.log.warning("Unexpected parameters passed to on_local_closed. Ignoring...")
            return

        server_id = self.local2server_id.get(local_id)
        if server_id:
            self.NotificationClosed(server_id, reason) #forward signal to apps
            self.remove_id(server_id)
        else:
            self.log.warning("Received a local close signal for an ID that is not in our database. This is unexpected. Ignoring...")

    def on_local_action(self, *args, **kwargs):
        self.log.debug("on_local_action")
        try:
            local_id = args[0]
            action_key = args[1]
        except IndexError:
            self.log.warning("Unexpected parameters passed to on_local_action. Ignoring...")
            return

        server_id = self.local2server_id.get(local_id)
        if server_id:
            self.ActionInvoked(server_id, action_key) #forward signal to apps
        else:
            self.log.warning("Received a local action signal for an ID that is not in our database. This is unexpected. Ignoring...")

def parse_args():
    parser = argparse.ArgumentParser(description="Daemon to selectively forward desktop notifications to another VM.")
    parser.add_argument("-v", help="Verbose logging.", action="store_true")
    parser.add_argument("-x", help="Exit the forwarder when it becomes idle.", action="store_true")
    parser.add_argument("-L", help="Local mode: Handle all notifications locally. Useful for debugging.", action="store_true")
    parser.add_argument("-F", help="Force mode: Forward all notifications. Overrides -L. This may cause usability issues.", action="store_true")
    parser.add_argument("--target", help="Target VM to forward notifications to (default: read from QubesDB /desktop-notification-target).")
    parser.add_argument("--dbus-address", help="Full address of a dedicated dbus instance to be used exclusively by the forwarder (default: start a new dbus instance). Do not use the default user session bus here!")
    return parser.parse_args()

def set_env(qdb):
    if not os.environ.get("DISPLAY"):
        os.environ.setdefault("DISPLAY", ":0")
    if not os.environ.get("DBUS_SESSION_BUS_ADDRESS"):
        user = (qdb.read("/default-user") or b"user").decode()
        try:
            uid = pwd.getpwnam(user).pw_uid
        except KeyError:
            uid = 1000
        os.environ.setdefault("DBUS_SESSION_BUS_ADDRESS", f"unix:path=/run/user/{uid}/bus")

def glib_error_handler(logger, pid, etype, val, tb):
    if isinstance(val, IdleTimeoutException):
        logger.info("Idle timeout. Exiting...")
    else:
        logger.error("\n".join(traceback.format_exception(etype, val, tb)))

    if pid:
        os.kill(pid, ossignal.SIGTERM)
    sys.exit(1)

def main():
    args = parse_args()
    logger = get_logger("notification-forwarder")

    qdb = qubesdb.QubesDB()
    set_env(qdb)

    if args.target:
        notification_vm = args.target
    else:
        notification_vm = (qdb.read("/desktop-notification-target") or b"").decode()

    vm = qdb.read("/name").decode()

    if notification_vm and notification_vm != vm:
        # Trick: We keep the previously running notification server by launching a private
        # dbus instance before launching our own notification server.
        paddr = args.dbus_address
        ppid = None
        if not paddr:
            launch_script = sys.path[0] + '/private-dbus/launch-private-dbus'
            paddr, ppid = launch_private_dbus(launch_script)
            logger.info(f"Launched private dbus. PID: {ppid}, Address: {paddr}")

        sys.excepthook = lambda e, v, t: glib_error_handler(logger, ppid, e, v, t) #for some reason GLib otherwise ignores Exceptions / hangs
        NotificationForwarder(notification_vm, paddr, verbose=args.v, local_mode=args.L, force_mode=args.F, exit_idle=args.x).run()
    else:
        logger.info("Configured to not be used in this VM. Exiting...")

    # Use the default locally running notification handler (usually the
    # mate-notification-daemon) otherwise. This is required in the receiving VM to
    # avoid loops and can also be employed by users to opt out of the functionality.
    sys.exit(0)

if __name__ == "__main__":
    main()
