depends () {
}

install () {
    if [ -h /lib ]; then
        inst_multiple /usr/lib/systemd/system/rescue.service.d/30_qubes.conf /usr/lib/systemd/system/emergency.service.d/30_qubes.conf
    else
        inst_multiple /lib/systemd/system/rescue.service.d/30_qubes.conf /lib/systemd/system/emergency.service.d/30_qubes.conf
    fi
}
