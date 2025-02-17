#!/bin/bash
# vim:fileencoding=utf-8:foldmethod=marker
#{{{ >>> Install Custom Lightdm-gtk-greeter

lightdm_install() {

FILE="lightdm-gtk-greeter lightdm.png"

	if [[ -f /etc/lightdm/lidhtdm-gtk-greeter ]];
	then
		mv /etc/lightdm-gtk-greeter /etc/lightdm-gtk-greeter.org
	fi

	if [[ -f /etc/lightdm/lidghtdm.png]];
	then
		mv /etc/lightdm/lightdm.png /etc/lightdm.png.org
	fi
sudo cp /home/batan/lcstartup/lightdm/lightdm.png /etc/lightdm/lightdm.png
sudo cp /home/batan/lcstartup/lightdm/lightdm.gtk.greeter /etc/lightdm/lightdm/lightdm.gtk.greeter

}


#}}}
