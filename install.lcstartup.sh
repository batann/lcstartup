#!/bin/bash
# vim:fileencoding=utf-8:foldmethod=marker

#{{{ >>>   Check Deps


check_deps() {

	DEPS_LCSTARTUP="lightdm lightdm-gtk-greeter plymouth grub2"
	for $pack in ${DEPS_LCSTARTUP[@]};
	do
		dpkg -s $pack >/dev/null 2>&1
		if [[ $? == 1 ]];
		then
			echo -e "\033[33mInstalling \033[31m${pack}\033[33m...\033[0m"
		sudo apt install $pack -y >/dev/null 2>&1
			fi
		done

	}

#}}}
#{{{   >>>   Prompt
display_prompt() {
	clear
echo -e "\033[37m# \033[32mThe following will be modified \033[37m: \033[0m               \033[0m"
echo -e "\033[37m━ \033[032m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ \033[37m━ \033[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━ \033[0m"
echo -e "\033[37m# \033[32m                 >>>>>>>       \033[37m: \033[37mlightdm-gtk-greeter         \033[0m"
echo -e "\033[37m# \033[32m                 >>>>>>>       \033[37m: \033[37mcustom grub configuration   \033[0m"
echo -e "\033[37m# \033[32m                 >>>>>>>       \033[37m: \033[37mplymouth-theme lc-linux     \033[0m"
echo -e "\033[37m━ \033[032m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ \033[37m━ \033[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━ \033[0m"
for x in $(seq 3 -1 0);
do
	tput cup 7 0
	echo -e "\033[37m# \033[32mInstalling in ... \033[37m${x} \033[32mSeconds\033[0m"
	sleep 5
	tput cup 7 0
done


}
#}}}
#{{{ >>>   Install Custom Grub


grub_install() {

	#THEME_DIR='/usr/share/grub/themes'
	THEME_DIR='/boot/grub/themes'
	THEME_NAME=''

	function echo_title() {     echo -ne "\033[1;44;37m${*}\033[0m\n"; }
	function echo_caption() {   echo -ne "\033[0;1;44m${*}\033[0m\n"; }
	function echo_bold() {      echo -ne "\033[0;1;34m${*}\033[0m\n"; }
	function echo_danger() {    echo -ne "\033[0;31m${*}\033[0m\n"; }
	function echo_success() {   echo -ne "\033[0;32m${*}\033[0m\n"; }
	function echo_warning() {   echo -ne "\033[0;33m${*}\033[0m\n"; }
	function echo_secondary() { echo -ne "\033[0;34m${*}\033[0m\n"; }
	function echo_info() {      echo -ne "\033[0;35m${*}\033[0m\n"; }
	function echo_primary() {   echo -ne "\033[0;36m${*}\033[0m\n"; }
	function echo_error() {     echo -ne "\033[0;1;31merror:\033[0;31m\t${*}\033[0m\n"; }
	function echo_label() {     echo -ne "\033[0;1;32m${*}:\033[0m\t"; }
	function echo_prompt() {    echo -ne "\033[0;36m${*}\033[0m "; }

	function splash() {
	    local hr
	    hr=" **$(printf "%${#1}s" | tr ' ' '*')** "
	    echo_title "${hr}"
	    echo_title " * $1 * "
	    echo_title "${hr}"
	    echo
	}

	function check_root() {
	    # Checking for root access and proceed if it is present
	    ROOT_UID=0
	    if [[ ! "${UID}" -eq "${ROOT_UID}" ]]; then
	        # Error message
	        echo_error 'Run me as root.'
	        echo_info 'try sudo ./install.sh'
	        exit 1
	    fi
	}

	function select_theme() {
	    themes=( 'Crt-amber' 'CyberEXS' 'Fallout' 'LC-smoking' 'LC-tokyo-night' 'Shodan' 'Tokyo-night' 'Vimix' 'Windows-10' 'Windows-11' 'Quit')

	    PS3=$(echo_prompt '\nChoose The Theme You Want: ')
	    select THEME_NAME in "${themes[@]}"; do
	        case "${THEME_NAME}" in
	            'Crt-amber')
	                splash 'Installing Crt-amber Theme...'
	                break;;
	            'Cyber-EXS')
	                splash 'Installing Cyber-EXS Theme...'
	                break;;
	            'Fallout')
	                splash 'Installing Fallout Theme...'
	                break;;
	            'LC-smoking')
	                splash 'Installing LC-smoking Theme...'
	                break;;
	            'LC-tokyo-night')
	                splash 'Installing LC-tokyo-night Theme...'
	                break;;
	            'Vimix')
	                splash 'Installing Vimix Theme...'
	                break;;
	            'Windows-10')
	                splash 'Installing Windows-10 Theme...'
	                break;;
	            'Windows-11')
	                splash 'Installing Windows-11 Theme...'
	                break;;
	            'Quit')
	                echo_info 'User requested exit...!'
	                exit 0;;
	            *) echo_warning "invalid option \"${REPLY}\"";;
	        esac
	    done
	}

	function backup() {
	    # Backup grub config
	    echo_info 'cp -an /etc/default/grub /etc/default/grub.bak'
	    cp -an /etc/default/grub /etc/default/grub.bak
	}

	function install_theme() {
	    # create themes directory if not exists
	    if [[ ! -d "${THEME_DIR}/${THEME_NAME}" ]]; then
	        # Copy theme
	        echo_primary "Installing ${THEME_NAME} theme..."

	        echo_info "mkdir -p \"${THEME_DIR}/${THEME_NAME}\""
	        mkdir -p "${THEME_DIR}/${THEME_NAME}"

	        echo_info "cp -a ./themes/\"${THEME_NAME}\"/* \"${THEME_DIR}/${THEME_NAME}\""
	        cp -a ./themes/"${THEME_NAME}"/* "${THEME_DIR}/${THEME_NAME}"
	    fi
	}

	function config_grub() {
	    echo_primary 'Enabling grub menu'
	    # remove default grub style if any
	    echo_info "sed -i '/GRUB_TIMEOUT_STYLE=/d' /etc/default/grub"
	    sed -i '/GRUB_TIMEOUT_STYLE=/d' /etc/default/grub

	    echo_info "echo 'GRUB_TIMEOUT_STYLE=\"menu\"' >> /etc/default/grub"
	    echo 'GRUB_TIMEOUT_STYLE="menu"' >> /etc/default/grub

	    #--------------------------------------------------

	    echo_primary 'Setting grub timeout to 60 seconds'
	    # remove default timeout if any
	    echo_info "sed -i '/GRUB_TIMEOUT=/d' /etc/default/grub"
	    sed -i '/GRUB_TIMEOUT=/d' /etc/default/grub

	    echo_info "echo 'GRUB_TIMEOUT=\"60\"' >> /etc/default/grub"
	    echo 'GRUB_TIMEOUT="60"' >> /etc/default/grub

	    #--------------------------------------------------

	    echo_primary "Setting ${THEME_NAME} as default"
	    # remove theme if any
	    echo_info "sed -i '/GRUB_THEME=/d' /etc/default/grub"
	    sed -i '/GRUB_THEME=/d' /etc/default/grub

	    echo_info "echo \"GRUB_THEME=\"${THEME_DIR}/${THEME_NAME}/theme.txt\"\" >> /etc/default/grub"
	    echo "GRUB_THEME=\"${THEME_DIR}/${THEME_NAME}/theme.txt\"" >> /etc/default/grub

	    #--------------------------------------------------

	    echo_primary 'Setting grub graphics mode to auto'
	    # remove default timeout if any
	    echo_info "sed -i '/GRUB_GFXMODE=/d' /etc/default/grub"
	    sed -i '/GRUB_GFXMODE=/d' /etc/default/grub

	    echo_info "echo 'GRUB_GFXMODE=\"auto\"' >> /etc/default/grub"
	    echo 'GRUB_GFXMODE="auto"' >> /etc/default/grub
	}

	function update_grub() {
	    # Update grub config
	    echo_primary 'Updating grub config...'
	    if [[ -x "$(command -v update-grub)" ]]; then
	        echo_info 'update-grub'
	        update-grub

	    elif [[ -x "$(command -v grub-mkconfig)" ]]; then
	        echo_info 'grub-mkconfig -o /boot/grub/grub.cfg'
	        grub-mkconfig -o /boot/grub/grub.cfg

	    elif [[ -x "$(command -v grub2-mkconfig)" ]]; then
	        if [[ -x "$(command -v zypper)" ]]; then
	            echo_info 'grub2-mkconfig -o /boot/grub2/grub.cfg'
	            grub2-mkconfig -o /boot/grub2/grub.cfg

	        elif [[ -x "$(command -v dnf)" ]]; then
	            echo_info 'grub2-mkconfig -o /boot/efi/EFI/fedora/grub.cfg'
	            grub2-mkconfig -o /boot/efi/EFI/fedora/grub.cfg
	        fi
	    fi
	}

	function main() {
	    splash 'The Matrix awaits you...'

	    check_root
	    select_theme

	    install_theme

	    config_grub
	    update_grub

	    echo_success 'Boot Theme Update Successful!'
	}

	main

}

#}}}
#{{{ >>>   Install plymouth
lc-plymouth() {
echo Please enter your sudo password if you are prompted to do so.
echo Installing the lcanon theme...
sudo mkdir /usr/share/plymouth/themes/lcanon
sudo cp -rf ./ /usr/share/plymouth/themes/lcanon
sudo update-alternatives --quiet --install /usr/share/plymouth/themes/default.plymouth default.plymouth /usr/share/plymouth/themes/lcanon/lcanon.plymouth 100
sudo update-alternatives --quiet --set default.plymouth /usr/share/plymouth/themes/lcanon/lcanon.plymouth
sudo update-initramfs -u
sudo update-grub2
echo Done!
echo Testing...
sudo plymouthd
sudo plymouth --show-splash
sleep 10
sudo plymouth quit
echo Done!
echo Have a nice day!

}

#}}}
#{{{ >>>   Install Custom Lightdm-gtk-greeter

lightdm_install() {

FILE="lightdm-gtk-greeter lightdm.png"

	if [[ -f /etc/lightdm/lidhtdm-gtk-greeter ]];
	then
		mv /etc/lightdm-gtk-greeter /etc/lightdm-gtk-greeter.org
	fi

	if [[ -f /etc/lightdm/lidghtdm.png ]];
	then
		mv /etc/lightdm/lightdm.png /etc/lightdm.png.org
	fi
sudo cp /home/batan/lcstartup/lightdm/lightdm.png /etc/lightdm/lightdm.png
sudo cp /home/batan/lcstartup/lightdm/lightdm.gtk.greeter /etc/lightdm/lightdm/lightdm.gtk.greeter

}


#}}}

display_prompt
check_deps
grub_install
lc-plymouth
lightdm_install


# Grub, Plymouth, Lightdm-Gtk-Greeter Install
