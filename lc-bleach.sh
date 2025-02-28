# vim:fileencoding=utf-8:foldmethod=marker
#{{{   variables
SYSTEM="cache clipboard custom desktop_entry localizations memory recent_documents rotated_logs tmp trash"

FIREFOX="backup cache cookies crash_reports dom forms passwords session_restore site_preferences url_history vacuum"

APT="autoclean autoremove clean package_lists"

DEEPSCAN="backup ds_store thumbs_db tmp"
#}}}
#{{{   functions
#{{{   clean functions
c_system(){
	for i in $(echo -e $SYSTEM);
do
	echo -e "\033[32mCleaning \033[31msystem.$i\033[0m"
	sudo bleachbit -c system.$i > /dev/null 2>&1
done
}

c_firefox(){
	for opt in $(echo $FIREFOX);
do
	echo -e "\033[32mCleaning \033[31mfirefox.$opt\033[0m"
	sudo bleachbit -c firefox.$opt > /dev/null 2>&1
done
}

c_apt(){
	for opt in $(echo $APT);
do
	echo -e "\033[32mCleaning \033[31mapt.$opt\033[0m"
	sudo bleachbit -c apt.$opt > /dev/null 2>&1
done
}

c_deepscan(){
	for opt in $(echo $DEEPSCAN);
do
	echo -e "\033[32mCleaning \033[31mdeepscan.$opt\033[0m"
	sudo bleachbit -c deepscan.$opt > /dev/null 2>&1
done
}

c_swapon(){
	echo -e "\033[32mRunning \033[31mswapon\033[0m"
	sudo swapon -a
}
c_swapoff(){
	echo -e "\033[32mRunning \033[31mswapoff\033[0m"
	sudo swapoff -a
}

c_cache(){
	echo -e "\033[32mCleaning \033[31mcache\033[0m"
#!/bin/bash

klin=$(tput el)
counter=$(find .cache -type f -name "*png"|wc -l)
for png in $(find .cache -type f -name "*png");
do
	echo -ne "\r${klin}\033[32mShredding left \033[34m$counter\033[0m"
	sudo shred -f -n1 -z -u /home/batan/$png
	#sudo rm -rf /home/batan/$png
	((counter--))
done
rm -r /home/batan/.cache/mozilla/firefox/* >/dev/null 2>&1
}

c_remove_flat(){
	echo -e "\033[32mRemoving \033[31munused flatpaks\033[0m"
	flatpak uninstall --unused >/dev/null 2>&1
}

#}}}
#{{{   update functions
u_update(){
COMM="sudo apt update"
}
u_upgrade(){
	COMM="sudo apt upgrade -y"
}
border(){
$COMM | awk '{
    # Store the incoming line in the buffer
    lines[NR % 5] = $0;

    # Track the longest line seen so far
    if (length($0) > global_max_len) {
        global_max_len = length($0);
    }

    # Only process when we have at least 5 lines and the line number is even
    if (NR >= 5 && NR % 2 == 0) {
        # ANSI escape code for green color
        green = "\033[32m";
        reset = "\033[0m";

        # Create top and bottom borders with the global max width
        top_border = green "╔";
        for (i = 1; i <= global_max_len + 2; i++) top_border = top_border "═";
        top_border = top_border "╗" reset;

        bottom_border = green "╚";
        for (i = 1; i <= global_max_len + 2; i++) bottom_border = bottom_border "═";
        bottom_border = bottom_border "╝" reset;

        # Use tput to move the cursor to row 10 and column 0 before printing
        system("tput cup 35 0");

        # Print the top border
        print top_border;

        # Print the 5 most recent lines, wrapped in the border
        for (i = 0; i < 5; i++) {
            printf("║ %-*s ║\n", global_max_len, lines[(NR - 5 + i) % 5]);
        }

        # Print the bottom border
        print bottom_border;

        # Sleep for 0.2 seconds to slow down the updates
        system("sleep 0.2");
    }
}'
}
u_flat(){
	echo -e "\033[34mUpdating \033[31mflatpak\033[0m"
flatpak update --app -y >/dev/null 2>&1
}

#}}}
#}}}

# {{{ >>>   job done
job_done(){
TIM=$(date +%H:%M)
notify-send -t 12000 "CLEANING" "<span color='Yellow' font='16px'>The system cleanup and update is done.\n</span><span color='Silver' font='16px'>It is</span><span color='White' font='16px'> $TIM </span><span color='Silver' font='16px'>time now</span>"
}
# }}}


#{{{   main
clear
c_system
c_firefox
c_apt
c_deepscan
c_remove_flat

c_cache
c_swapoff
c_swapon



u_update
tput cup 35 0
border
u_upgrade
tput cup 41 0
u_flat
job_done
#}}}
