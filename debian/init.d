#!/bin/sh
### BEGIN INIT INFO
# Provides:          qubes-core-agent
# Required-Start:    $network $local_fs $remote_fs
# Required-Stop:
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Qubes qrexec agent
# Description:       The qrexec agent runs in qubes domU domains. It runs
#                    commands on request from dom0.
### END INIT INFO

# Author: Davíð Steinn Geirsson <david@dsg.is>
# Most of this script is copied from vm-init.d/qubes-core with 
# some fedora-specific stuff removed.

# PATH should only include /usr/* if it runs after the mountnfs.sh script
PATH=/sbin:/usr/sbin:/bin:/usr/bin
DESC=qrexec-agent
NAME=qrexec-agent
DAEMON=/usr/lib/qubes/qrexec-agent
DAEMON_ARGS=""
PIDFILE=/var/run/$NAME.pid
SCRIPTNAME=/etc/init.d/$NAME

# Exit if the package is not installed
[ -x $DAEMON ] || exit 0

# Read configuration variable file if it is present
[ -r /etc/default/$NAME ] && . /etc/default/$NAME

# Load the VERBOSE setting and other rcS variables
. /lib/init/vars.sh

# Define LSB log_* functions.
# Depend on lsb-base (>= 3.0-6) to ensure that this file is present.
. /lib/lsb/init-functions

#
# Function that starts the daemon/service
#
do_start()
{
	# Return
	#   0 if daemon has been started
	#   1 if daemon was already running
	#   2 if daemon could not be started

	# Ensure necessary modules are loaded
	modprobe xen_evtchn
	modprobe u2mfn


	# Set permissions to /proc/xen/xenbus, so normal user can use xenstore-read
	chmod 666 /proc/xen/xenbus
	# Set permissions to files needed to listen at vchan
	chmod 666 /proc/u2mfn

	mkdir -p /var/run/xen-hotplug

	name=$(/usr/sbin/xenstore-read name)
	if ! [ -f /etc/this-is-dvm ] ; then
		# we don't want to set hostname for DispVM
		# because it makes some of the pre-created dotfiles invalid (e.g. .kde/cache-<hostname>)
		# (let's be frank: nobody's gonna use xterm on DispVM)
		if ! [ -z "$name" ]; then
			echo $name > /etc/hostname
			hostname $name
			grep '127.0.1.1' /etc/hosts > /dev/null
			if [ $? -ne 0 ]; then
				echo "127.0.1.1 $name" >> /etc/hosts
			else
				sed -i "s/127\.0\.1\.1.*/127.0.1.1 $name/" /etc/hosts
			fi
		fi
	fi

	timezone=`/usr/sbin/xenstore-read qubes-timezone 2> /dev/null`
	if [ -n "$timezone" ]; then
		ln -f /usr/share/zoneinfo/$timezone /etc/localtime
	fi

	# Set IP address again (besides action in udev rules); this is needed by
	# DispVM (to override DispVM-template IP) and in case when qubes-ip was
	# called by udev before loading evtchn kernel module - in which case
	# xenstore-read fails
	INTERFACE=eth0 /usr/lib/qubes/setup-ip

	mkdir -p /var/run/qubes

	if [ -e /dev/xvdb ] ; then
		resize2fs /dev/xvdb 2> /dev/null || echo "'resize2fs /dev/xvdb' failed"
		mount /rw

		if ! [ -d /rw/home ] ; then
			echo
			echo "--> Virgin boot of the VM: Linking /home to /rw/home"

			mkdir -p /rw/config
			touch /rw/config/rc.local

			mkdir -p /rw/home
			cp -a /home.orig/user /rw/home

			mkdir -p /rw/usrlocal
			cp -a /usr/local.orig/* /rw/usrlocal

			touch /var/lib/qubes/first-boot-completed
		fi
	fi
	if [ -L /home ]; then
		rm /home
		mkdir /home
	fi
	mount /home

	[ -x /rw/config/rc.local ] && /rw/config/rc.local


	start-stop-daemon --start --quiet -b --pidfile $PIDFILE --exec $DAEMON --test > /dev/null \
		|| return 1
	start-stop-daemon --start --quiet -b --pidfile $PIDFILE --exec $DAEMON -- \
		$DAEMON_ARGS \
		|| return 2
	# Add code here, if necessary, that waits for the process to be ready
	# to handle requests from services started subsequently which depend
	# on this one.  As a last resort, sleep for some time.
}

do_stop()
{
	# Return
	#   0 if daemon has been stopped
	#   1 if daemon was already stopped
	#   2 if daemon could not be stopped
	#   other if a failure occurred
	start-stop-daemon --stop --quiet --retry=TERM/30/KILL/5 --pidfile $PIDFILE --name $NAME
	RETVAL="$?"
	[ "$RETVAL" = 2 ] && return 2
	# Wait for children to finish too if this is a daemon that forks
	# and if the daemon is only ever run from this initscript.
	# If the above conditions are not satisfied then add some other code
	# that waits for the process to drop all resources that could be
	# needed by services started subsequently.  A last resort is to
	# sleep for some time.
	start-stop-daemon --stop --quiet --oknodo --retry=0/30/KILL/5 --exec $DAEMON
	[ "$?" = 2 ] && return 2
	# Many daemons don't delete their pidfiles when they exit.
	rm -f $PIDFILE
	return "$RETVAL"
}

#
# Function that sends a SIGHUP to the daemon/service
#
do_reload() {
	#
	# If the daemon can reload its configuration without
	# restarting (for example, when it is sent a SIGHUP),
	# then implement that here.
	#
	start-stop-daemon --stop --signal 1 --quiet --pidfile $PIDFILE --name $NAME
	return 0
}

case "$1" in
  start)
    [ "$VERBOSE" != no ] && log_daemon_msg "Starting $DESC " "$NAME"
    do_start
    case "$?" in
		0|1) [ "$VERBOSE" != no ] && log_end_msg 0 ;;
		2) [ "$VERBOSE" != no ] && log_end_msg 1 ;;
	esac
  ;;
  stop)
	[ "$VERBOSE" != no ] && log_daemon_msg "Stopping $DESC" "$NAME"
	do_stop
	case "$?" in
		0|1) [ "$VERBOSE" != no ] && log_end_msg 0 ;;
		2) [ "$VERBOSE" != no ] && log_end_msg 1 ;;
	esac
	;;
  status)
       status_of_proc "$DAEMON" "$NAME" && exit 0 || exit $?
       ;;
  #reload|force-reload)
	#
	# If do_reload() is not implemented then leave this commented out
	# and leave 'force-reload' as an alias for 'restart'.
	#
	#log_daemon_msg "Reloading $DESC" "$NAME"
	#do_reload
	#log_end_msg $?
	#;;
  restart|force-reload)
	#
	# If the "reload" option is implemented then remove the
	# 'force-reload' alias
	#
	log_daemon_msg "Restarting $DESC" "$NAME"
	do_stop
	case "$?" in
	  0|1)
		do_start
		case "$?" in
			0) log_end_msg 0 ;;
			1) log_end_msg 1 ;; # Old process is still running
			*) log_end_msg 1 ;; # Failed to start
		esac
		;;
	  *)
	  	# Failed to stop
		log_end_msg 1
		;;
	esac
	;;
  *)
	#echo "Usage: $SCRIPTNAME {start|stop|restart|reload|force-reload}" >&2
	echo "Usage: $SCRIPTNAME {start|stop|status|restart|force-reload}" >&2
	exit 3
	;;
esac

:
