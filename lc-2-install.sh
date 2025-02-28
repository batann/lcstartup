#!/bin/bash
# vim:fileencoding=utf-8:foldmethod=marker
#{{{ >>> Script Information
#author			:	fairdinkum batan
#mail			:	12982@tutanota.com
#description	:	In contrast to the script lc-install.sh, which runs compleatly
#			    :   automatically, this script is a continuation script and rather then
#			    :   installing packages and software that might not be needed,
#			    :   it will prompt the user at the very beginning anddisplay all the available # 			   :   options, only after user interaction, which happenes at the very beginning
#			    :   and only then, the script will run and execute the parts needed
-----------------------------------------------------------------------------------------------
#}}}
#{{{###  clear command and ansi coloring
clear
Black='\033[0;30m'
Red='\033[0;31m'
Green='\033[0;32m'
Blue='\033[0;34m'
Purple='\033[0;35m'
Cyan='\033[0;36m'
Yellow='\033[1;33m'
White='\033[1;37m'
BBlue='\e[0;104m'
BBlack='\e[0;100m'
RRed='\e[0;100m'
GGreen='\e[0;100m'
YYellow='\e[0;100m'
BBlue='\e[0;100m'
PPurple='\e[0;100m'
CCyan='\e[0;100m'
WWhite='\e[0;100m'

#}}}

#{{{ >>> Script Display and variables
#!/bin/bash

# ANSI Colors
Black='\033[0;30m'
Red='\033[0;31m'
Green='\033[0;32m'
Blue='\033[0;34m'
Purple='\033[0;35m'
Cyan='\033[0;36m'
Yellow='\033[1;33m'
White='\033[1;37m'
NC='\033[0m'

# Initialize individual answer variables (aa1-aa30)
for i in {1..30}; do
    declare "aa$i=0"
done

# Questions and their answers (0 = No, 1 = Yes)
QUESTIONS=(
	"| 01) |Install |Cairo-Dock                 |"
	"| 02) |Install |Steam Installer for Gaming |"
	"| 03) |Install |Gnome-Boxes                |"
	"| 04) |Install |Ollama and Mistral Model   |"
	"| 05) |Install |Docker and Funkwhale       |"
	"| 06) |Install |Anonsurf (Parrot OS)       |"
	"| 07) |Install |Neovim and Codium          |"
	"| 08) |Install |Cubic                      |"
	"| 09) |Install |Flatpak                    |"
	"| 10) |Install |superfile (file-manager)   |"
	"| 11) |Create  |System cleanup script      |"
	"| 12) |Install |Go language                |"
	"| 13) |Build   |                           |"
	"| 14) |Install |Cursor (editor)            |"
	"| 15) |Install |Nix (package manager)      |"
	"| 16) |Install |Gnome-base (desktop)       |"
	"| 17) |Install |Sway (desktop)             |"
	"| 18) |Install |Dwm (suckless desktop)     |"
	"| 19) |Install |Budgie (desktop)           |"
	"| 20) |        |                           |"
	"| 21) |        |                           |"
	"| 22) |        |                           |"
	"| 23) |        |                           |"
	"| 24) |        |                           |"
	"| 25) |Install |LC-Grub,Plymouth,lightdm   |"
	"| 26) |        |                           |"
	"| 27) |Install |Kodi and its deps          |"
	"| 28) |Create  |and exec fin2.sh           |"
	"| 29) |RUN     |LC-INSTALL.SH              |"
)

#}}}

#{{{ >>> Script Continuation
ANSWERS=(0 0 0 0)  # Default all answers to No
NUM_QUESTIONS=${#QUESTIONS[@]}
selected=0  # Current selected row (-1 for Cancel, NUM_QUESTIONS for Accept)

# Function to display the radio menu
DISPLAY_MENU() {
    clear

    # Display Cancel option
    if [[ $selected -eq -1 ]]; then
        echo -e "${White}${Blue}[ Cancel ]${NC}"
    else
        echo -e "  Cancel  "
    fi

    echo "  +-----+--------+---------------------------+"

    # Display questions and their Yes/No options
    for ((i=0; i<NUM_QUESTIONS; i++)); do
        if [[ $selected -eq $i ]]; then
            echo -ne "${White}${Blue}>"
        else
            echo -ne " "
        fi

        echo -ne " ${QUESTIONS[i]}"

        # Move cursor to position 40
        printf "%*s" $((40 - ${#QUESTIONS[i]})) ""

        if [[ ${ANSWERS[i]} -eq 1 ]]; then
            echo -e "[${Green}Yes${NC}] / No "
        else
            echo -e "Yes / [${Red}No${NC}] "
        fi
    done

    echo "  +-----+--------+---------------------------+"

    # Display Accept option
    if [[ $selected -eq $NUM_QUESTIONS ]]; then
        echo -e "${White}${Blue}[ Accept and Continue ]${NC}"
    else
        echo -e "  Accept and Continue  "
    fi
}

# Main loop
while true; do
    DISPLAY_MENU

    read -sn1 key

    if [[ $key == $'\e' ]]; then
        read -sn1 key
        if [[ $key == '[' ]]; then
            read -sn1 key
            case $key in
                'A') # Up arrow
                    ((selected--))
                    if [[ $selected -lt -1 ]]; then
                        selected=$NUM_QUESTIONS
                    fi
                    ;;
                'B') # Down arrow
                    ((selected++))
                    if [[ $selected -gt $NUM_QUESTIONS ]]; then
                        selected=-1
                    fi
                    ;;
                'C') # Right arrow
                    if [[ $selected -ge 0 && $selected -lt NUM_QUESTIONS ]]; then
                        ANSWERS[selected]=1
                    fi
                    ;;
                'D') # Left arrow
                    if [[ $selected -ge 0 && $selected -lt NUM_QUESTIONS ]]; then
                        ANSWERS[selected]=0
                    fi
                    ;;
            esac
        fi
    elif [[ $key == '' ]]; then  # Enter key
        if [[ $selected -eq -1 ]]; then
            echo "Operation cancelled."
            exit 1
        elif [[ $selected -eq $NUM_QUESTIONS ]]; then
            clear
            echo "Selected answers:"
            for ((i=0; i<NUM_QUESTIONS; i++)); do
                echo "${QUESTIONS[i]}: ${ANSWERS[i]}"
                # Update individual variables
                declare "aa$((i+1))=${ANSWERS[i]}"
            done
            break
        fi
    fi
done
#}}}
#{{{###  functions
###   To think about:
#     function that can be run to install app specific dependencies, where by they are usually
#     stored in a variable and is named in each case different...
#}}}
#{{{###  DEPS

DEPS_STEAM="libatomic1 libbsd0 libcrypt1 libdrm-amdgpu1 libdrm-intel1 libdrm-nouveau2 libdrm-radeon1 libdrm2 libedit2 libelf1 libexpat1 libffi8 libgl1-mesa-dri libgl1 libglapi-mesa libglvnd0 libglx-mesa0 libglx0 libgpg-error0 libicu72 libllvm15 liblzma5 libmd0 libpciaccess0 libsensors5 libstdc++6 libtinfo6 libudev1 libva-x11-2 libva2 libx11-6 libx11-xcb1 libxau6 libxcb-dri2-0 libxcb-dri3-0 libxcb-glx0 libxcb-present0 libxcb-randr0 libxcb-shm0 libxcb-sync1 libxcb-xfixes0 libxcb1 libxdmcp6 libxext6 libxfixes3 libxi6 libxinerama1 libxml2 libxshmfence1 libxxf86vm1 libz3-4 libzstd1 steam-installer steam-libs-i386 steam-libs steam-libs zlib1g"
#}}}
#{{{###  User Prompts

#}}}

read -n1 -p "Enter [ANY] to continue..." xxx


if [[ $aa1 -eq 1 ]]; then
#{{{###  Cairo Dock
DEPS_CAIRO="cairo-dock-alsamixer-plug-in cairo-dock-animated-icons-plug-in cairo-dock-cairo-penguin-plug-in cairo-dock-clipper-plug-in cairo-dock-clock-plug-in cairo-dock-core cairo-dock-dbus-plug-in cairo-dock-desklet-rendering-plug-in cairo-dock-dialog-rendering-plug-in cairo-dock-dnd2share-plug-in cairo-dock-drop-indicator-plug-in cairo-dock-dustbin-plug-in cairo-dock-folders-plug-in cairo-dock-gmenu-plug-in cairo-dock-icon-effect-plug-in cairo-dock-illusion-plug-in cairo-dock-kde-integration-plug-in cairo-dock-keyboard-indicator-plug-in cairo-dock-logout-plug-in cairo-dock-mail-plug-in cairo-dock-messaging-menu-plug-in cairo-dock-motion-blur-plug-in cairo-dock-musicplayer-plug-in cairo-dock-netspeed-plug-in cairo-dock-quick-browser-plug-in cairo-dock-recent-events-plug-in cairo-dock-remote-control-plug-in cairo-dock-rendering-plug-in cairo-dock-rssreader-plug-in cairo-dock-showdesktop-plug-in cairo-dock-showmouse-plug-in cairo-dock-slider-plug-in cairo-dock-stack-plug-in cairo-dock-switcher-plug-in cairo-dock-system-monitor-plug-in cairo-dock-systray-plug-in cairo-dock-terminal-plug-in cairo-dock-toons-plug-in cairo-dock-weather-plug-in cairo-dock-wifi-plug-in cairo-dock-xgamma-plug-in "
for i in ${DEPS_CAIRO[@]}; do
	dpkg -s $i > /dev/null 2>&1
	if [ $? -eq 1 ]; then
		echo -e "\033[33m Installing \033[34m$i \033[0m"
		sudo apt install $i -y > /dev/null 2>&1
	fi
done

#}}}
fi
if [[ $aa2 -eq 1 ]]; then
#{{{###  Install Steam for Gaming
sudo apt-get update
for package in ${DEPS_STEAM[@]}; do
	dpkg -s $package >/dev/null 2>&1
	if [ $? -ne 0 ]; then
		echo -e "\033[33mInstalling \033[4m$package \033[33m...\033[0m"
		sudo apt-get install -y $package>>/dev/null 2>&1
	fi
done

#}}}
fi
if [[ $aa3 -eq 1 ]]; then
#{{{ ### install gnom-boxes
DEPS_BOXES="dmeventd gnome-boxes gnutls-bin ibverbs-providers ipxe-qemu libaio1 libboost-thread1.74.0 libbrlapi0.8 libcacard0 libcapstone4 libcue2 libdevmapper-event1.02.1 libexecs0 libexempi8 libexiv2-27 libfdt1 libfmt9 libgexiv2-2 libgfapi0 libgfrpc0 libgfxdr0 libglusterfs0 libgnutls-dane0 libgsf-1-114 libgsf-1-common libgxps2 libibverbs1 libiptcdata0 libiscsi7 liblvm2cmd2.03 libosinfo-1.0-0 libosinfo-bin libosinfo-l10n libphodav-3.0-0 libphodav-3.0-common librados2 librbd1 librdmacm1 libslirp0 libspice-client-glib-2.0-8 libspice-client-gtk-3.0-5 libspice-server1 libssh-4 libtotem-plparser-common libtotem-plparser18 libtpms0 libtracker-sparql-3.0-0 libunbound8 libusbredirhost1 libusbredirparser1 libvdeplug2 libvirglrenderer1 libvirt-daemon-driver-lxc libvirt-daemon-driver-qemu libvirt-daemon-driver-vbox libvirt-daemon-driver-xen libvirt-daemon libvirt-glib-1.0-0 libvirt-glib-1.0-data libvirt-l10n libvirt0 libxencall1 libxendevicemodel1 libxenevtchn1 libxenforeignmemory1 libxengnttab1 libxenhypfs1 libxenmisc4.17 libxenstore4 libxentoolcore1 libxentoollog1 lvm2 netcat-openbsd osinfo-db ovmf qemu-block-extra qemu-system-common qemu-system-data qemu-system-gui qemu-system-x86 qemu-utils seabios spice-client-glib-usb-acl-helper swtpm-libs swtpm-tools swtpm thin-provisioning-tools tracker-extract tracker-miner-fs tracker spice-vdagent spice-webdavd"

clear
for i in ${DEPS_BOXES[@]};
do
	dpkg -s $i>/dev/null 2>&1
	if [[ $? == "1" ]];
	then
		sudo apt install $i -y
		fi
done
#}}}
fi
if [[ $aa4 -eq 1 ]]; then
#{{{###  Ollama and Mistral
sudo apt install

for file in python3-venv python3-pip pipx python3-dev; do
	dpkg -s $file &>/dev/null 2>&1
	if [[ $? -eq 1 ]]; then
		echo -e "\033[0;33mInstalling \033[0;32m$file\033[0m"
		sudo apt install -y $file >/dev/null 2>&1
	fi
	done

python3 -m .venv /home/batan/.venv
source /home/batan/.venv/bin/activate

  pipx install langchain sentence_transformers faiss-cpu ctransformers


  cat<< 'EOL'>mini-lm-file-creation.py
  """
This script creates a database of information gathered from local text files.
"""

from langchain.document_loaders import DirectoryLoader, TextLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.embeddings import HuggingFaceEmbeddings
from langchain.vectorstores import FAISS

# define what documents to load
loader = DirectoryLoader("./", glob="*.txt", loader_cls=TextLoader)

# interpret information in the documents
documents = loader.load()
splitter = RecursiveCharacterTextSplitter(chunk_size=500,
                                          chunk_overlap=50)
texts = splitter.split_documents(documents)
embeddings = HuggingFaceEmbeddings(
    model_name="sentence-transformers/all-MiniLM-L6-v2",
    model_kwargs={'device': 'cpu'})

# create and save the local database
db = FAISS.from_documents(texts, embeddings)
db.save_local("faiss")
EOL

cat<< 'EOL'>LM-reads-vector-FAISS-database.py
"""
This script creates a database of information gathered from local text files.
"""

from langchain.document_loaders import DirectoryLoader, TextLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.embeddings import HuggingFaceEmbeddings
from langchain.vectorstores import FAISS

# define what documents to load
loader = DirectoryLoader("./", glob="*.txt", loader_cls=TextLoader)

# interpret information in the documents
documents = loader.load()
splitter = RecursiveCharacterTextSplitter(chunk_size=500,
                                          chunk_overlap=50)
texts = splitter.split_documents(documents)
embeddings = HuggingFaceEmbeddings(
    model_name="sentence-transformers/all-MiniLM-L6-v2",
    model_kwargs={'device': 'cpu'})

# create and save the local database
db = FAISS.from_documents(texts, embeddings)
db.save_local("faiss")
EOL

#}}}
fi
if [[ $aa5 -eq 1 ]]; then
# #{{{>>>   Install docker and funkwhale
sudo apt update && sudo apt upgrade -y
DEPS_DOCKER_DEBIAN="docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin ca-certificates curl gnupg lsb-release"

for pak in ${DEPS_DOCKER_DEBIAN[@]};
do
	dpkg -s $pak >/dev/null 2>&1
	if [[ $? == '1' ]];
	then
		echo -e "\033[33mInstalling $pak\033[0m"
		sudo apt install $pak -y
	else
		echo -e "\033[33m$pak already installed\033[0m"
	fi
done

# Function to display error and exit
error_exit() {
  echo "Error: $1" >&2
  exit 1
}

# Verifying Debian and Ubuntu
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
	if [ -f /etc/os-release ]; then
		# Source the os-release file to get distribution info
		. /etc/os-release
		OS=$NAME
		VER=$VERSION_ID
	elif [ -f /etc/lsb-release ]; then
		# For older systems, use lsb_release if available
		. /etc/lsb-release
		OS=$DISTRIB_ID
		VER=$DISTRIB_RELEASE
	elif [ -f /etc/debian_version ]; then
		# For Debian-based systems without os-release
		OS="Debian"
		VER=$(cat /etc/debian_version)
	else
		# Unknown Linux system
		OS=$(uname -s)
		VER=$(uname -r)
	fi
fi
echo -e "${B}Detected Linux system:$OS"
DITRIB=$OS



# Installing Docker on Ubuntu

#if [[ $DITRIB == 'Ubuntu']];
#then
#
#for dependency in ${DEPS_DOCKER_UBUNTU[@]};
#do
#	dpkg -s $dependency >/dev/null 2>&1
#	if [[ $? == '1' ]];
#then
#	echo -e "\033[33mInstalling $dependency\033[0m"
#	sudo apt install $dependency -y
#else
#	echo -e "\033[33m$dependency already installed\033[0m"
#	fi
#


#if [[ $DISTRIB == 'Debian']];
#then

# Update the package list and install prerequisites
echo "Updating package list and installing prerequisites..."
sudo apt update || error_exit "Failed to update package list"
sudo apt install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release || error_exit "Failed to install prerequisites"

# Add Docker's official GPG key
echo "Adding Docker's official GPG key..."
sudo mkdir -p /etc/apt/keyrings || error_exit "Failed to create keyring directory"
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg || error_exit "Failed to add Docker's GPG key"

# Set up the Docker repository
echo "Setting up Docker repository..."
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null || error_exit "Failed to set up Docker repository"

# Update package list and install Docker
echo "Installing Docker..."
sudo apt update || error_exit "Failed to update package list"

#if [[ $DITRIB == 'Debian']];
#then
#
#for dependency in ${DEPS_DOCKER_DEBIAN[@]};
#do
#	dpkg -s $dependency >/dev/null 2>&1
#	if [[ $? == '1' ]];
#then
#	echo -e "\033[33mInstalling $dependency\033[0m"
#	sudo apt install $dependency -y
#else
#	echo -e "\033[33m$dependency already installed\033[0m"
#	fi
#done
#sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin || error_exit "Failed to install Docker"

# Verify Docker installation
echo "Verifying Docker installation..."
docker --version || error_exit "Docker installation failed"

# Prompt for Funkwhale configuration
read -e -p "Enter the Funkwhale hostname (e.g., yourdomain.funkwhale): " -i 'funkwhale' FUNKWHALE_HOSTNAME
read -e -p "Enter the full path for Funkwhale data directory (e.g., /path/to/data): " -i '/media/batan/100/Music/data' DATA_DIR
read -e -p "Enter the full path for Funkwhale music directory (e.g., /path/to/music): " -i '/media/batan/100/Music/' MUSIC_DIR

if [[ ! -d "$DATA_DIR" ]]; then
	mkdir -p "$DATA_DIR"
fi


# Check if directories exist
[ ! -d "$DATA_DIR" ] && error_exit "Data directory does not exist: $DATA_DIR"
[ ! -d "$MUSIC_DIR" ] && error_exit "Music directory does not exist: $MUSIC_DIR"

# Run the Funkwhale Docker container
echo "Running Funkwhale container..."
docker run \
    --name=funkwhale \
    -e FUNKWHALE_HOSTNAME="$FUNKWHALE_HOSTNAME" \
    -e NESTED_PROXY=0 \
    -v "$DATA_DIR:/data" \
    -v "$MUSIC_DIR:/music:ro" \
    -p 3030:80 \
    thetarkus/funkwhale || error_exit "Failed to start Funkwhale container"

echo "Funkwhale is now running. Access it at http://localhost:3030 or http://$FUNKWHALE_HOSTNAME"



#}}}
fi
if [[ $aa6 -eq 1 ]]; then
#{{{ >>> Install Anonsurf (Parrot OS)
git clone https://github.com/ParrotSec/anonsurf.git
cd anonsurf
sudo make
sudo make install
cd
#}}}
fi
if [[ $aa7 -eq 1 ]]; then
#{{{ >>>   Buiulding latest neovim incl Codium autocompleation
#{{{ >>>   Install neovim
DEPS_NVIM_BUILD="git ninja-build gettext cmake unzip curl"

for pak in ${DEPS_NVIM_BUILD[@]};
do
	dpgk -s $pak>/dev/null 2>&1
	if [[ $? == 1 ]]; then
		echo -e "\o33[34mInstalling \033[31m$pak \033[34m...\033[0m"
		sudo apt install $pak -y >/dev/null 2>&1
fi
done

git clone https://github.com/neovim/neovim.git
cd neovim
git checkout stable
make CMAKE_BUILD_TYPE=RelWithDebInfo
sudo make install
cd /home/batan

# Install neovim with codium autocompleation
clear
echo -e "\033[44m\033[30mInstalling neovim with codium autocompleation\033[0m"
git clone https://github.com/Exafunction/codeium.vim /home/batan/.config/nvim/pack/Exafunction/start/codeium.vim
#}}}
#{{{ >>>   Create init.vim.codium

cat << 'EOL' > /home/batan/.config/nvim/init.vim.codium
"# Codium Config
#disable default keybindings
vim.g.codeium_disable_bindings = 1
#disable codium by default
vim.g.codeium_enabled = false
#show codium in status line
vim.api.nvim_call_function("codeium#GetStatusString", {})
EOL
#}}}
#{{{ >>>   Create init.vim
cat << 'EOL' > /home/batan/.config/nvim/init.vim
"# vim:fileencoding=utf-8:foldmethod=marker
"#{{{ >>>   LEADER MAPPINGS
let mapleader = ","
nnoremap <Leader>te :terminal<CR>
nnoremap <Leader>tc :terminal<CR>sudo -u batan bash $HOME/check/vim.cmd.sh <CR>
nnoremap <Leader>xc :w !xclip -selection clipboard<CR>	"copy page to clipboard
nnoremap <leader>dd :Lexplore %:p:h<CR>		"open netrw in 20% of the screen to teh left
nnoremap <Leader>da :Lexplore<CR>
nnoremap <leader>vv :split $MYVIMRC<CR>		"edit vimrc
nnoremap <leader>sv :source $MYVIMRC<CR>	"source vimrc
nnoremap <leader>ra :<C-U>RangerChooser<CR>
nnoremap <leader>be :w<CR>:!bash %<CR>


nmap <F8> :TagbarToggle<CR>				"tagbar toggle
"#}}}
"#{{{ >>>   Leader Bindings specific for tmux
" Send the current line to another tmux pane
nnoremap <leader>t :execute '!tmux send-keys -t :. "'.getline('.').'" Enter'<CR>

" Send the entire buffer to another tmux pane
nnoremap <leader>T :w !tmux send-keys -t :. "bash" Enter<CR>

"#}}}
"#{{{ >>>   COMMON CONFIGS
set wildmode=longest,list,full
set wildmenu

if filereadable("/etc/vim/vimrc.local")
		source /etc/vim/vimrc.local
	endif

	if $COLORTERM == 'gnome-terminal'
    set t_Co=256
endif

if filereadable("/etc/vim/vimrc.local")
		source /etc/vim/vimrc.local
	endif
 if exists('$TMUX')  " Support resizing in tmux
   set ttymouse=xterm2
   endif
syntax on
filetype plugin indent on
set laststatus=2
set so=7
set foldcolumn=1
set encoding=utf8
set ffs=unix,dos
set cmdheight=1
set hlsearch
set lazyredraw
set magic
set showmatch
set mat=2
set foldcolumn=1
set encoding=utf8
set smarttab
set shiftwidth=4
set tabstop=4
set lbr
set tw=500
set ai "Auto indent
set si "Smart indent
set nobackup
set nowb
set nocp
set autowrite
set hidden
set mouse=a
set noswapfile
set nu
set relativenumber
set t_Co=256
set cursorcolumn
set cursorline
set ruler
set scrolloff=10
"#}}}
"#{{{ >>>   Netrw
let g:netrw_menu = 1
let g:netrw_preview = 1
let g:netrw_winsize = 20
let g:netrw_banner = 0
let g:netrw_lifestyle = 1
let g:netrw_liststyle = 3
let g:netrw_browse_split = 4
"#}}}
"#{{{ >>>   TEMPLATES
autocmd! BufNewFile *.sh 0r ~/.config/nvim/templates/sklt.sh
autocmd! BufNewFile *popup.html 0r ~/.config/nvim/templates/popup.html
autocmd! BufNewFile *popup.css 0r ~/.config/nvim/templates/popup.css
autocmd! BufNewFile *popup.js 0r ~/.config/nvim/templates/popup.js
autocmd! BufNewFile *.sh 0r ~/.config/nvim/templates/sklt.t.sh
autocmd! BufNewFile *.html 0r ~/.config/nvim/templates/sklt.html
autocmd! BufNewFile *.txt 0r ~/.config/nvim/templates/sklt.txt
autocmd! BufNewFile *.w.wiki 0r ~/.config/nvim/templates/sklt.w.wiki
autocmd! BufNewFile /home/batan/.config/reminder/*.rem 0r ~/.config/nvim/templates/sklt.rem | normal! 11G| +START
if has ('autocmd') " Remain compatible with earlier versions
 augroup vimrc     " Source vim configuration upon save
    autocmd! BufWritePost $MYVIMRC source % | echom "Reloaded " . $MYVIMRC | redraw
    autocmd! BufWritePost $MYGVIMRC if has('gui_running') | so % | echom "Reloaded " . $MYGVIMRC | endif | redraw
  augroup END
endif " has autocmd
"#}}}
"#{{{ >>>   Code snipet dpkg check if not
command! -nargs=0 Chek :call DpkgCHK()
function DpkgCHK()
	let g:package1 = input('Enter the name of package1:  ')
	execute "normal! i dpgk -s ".g:package1.">/dev/null 2>&1 \r"
	execute "normal! iif [[ $? == 1 ]]; then\r"
	execute "normal! iecho -e '\033[33mInstalling \033[31m".g.package1."\033[33m...\033[0m\r'"
	execute "normal! sudo apt install ".g:package1." -y >/dev/null 2>&1\r"

endfunction
"#}}}
"#{{{ >>>   tasks ?
" default task report type
let g:task_report_name     = 'next'
" custom reports have to be listed explicitly to make them available
let g:task_report_command  = []
" whether the field under the cursor is highlighted
let g:task_highlight_field = 1
" can not make change to task data when set to 1
let g:task_readonly        = 0
" vim built-in term for task undo in gvim
let g:task_gui_term        = 1
" allows user to override task configurations. Seperated by space. Defaults to ''
let g:task_rc_override     = 'rc.defaultwidth=999'
" default fields to ask when adding a new task
let g:task_default_prompt  = ['due', 'description']
" whether the info window is splited vertically
let g:task_info_vsplit     = 0
" info window size
let g:task_info_size       = 15
" info window position
let g:task_info_position   = 'belowright'
" directory to store log files defaults to taskwarrior data.location
let g:task_log_directory   = '~/.task'
" max number of historical entries
let g:task_log_max         = '20'
" forward arrow shown on statusline
let g:task_left_arrow      = ' <<'
" backward arrow ...
let g:task_left_arrow      = '>> '
"#}}}
"#{{{ >>>   Vimwiki
set nocompatible
filetype plugin on
syntax on
let g:vimwiki_list = [{
  \ 'path': '$HOME/10/vimwiki/templates/',
  \ 'template_path': '$HOME/10/vimwiki/templates',
  \ 'template_default': 'default',
  \ 'template_ext': '.html'}]
let g:vimwiki_hl_headers = 1
let wiki_2 = {}
let wiki_2.path = '/home/batan/10/vimwiki/vimwiki2/'
let wiki_2.path_html = '/home/batan/10/vimwiki/vimwiki2_html/'

let wiki_1 = {}
let wiki_1.path = '/home/batan/10/vimwiki/'
let wiki_1.path_html = '/home/batan/10/vimwiki_html/'

let wiki_3 = {}
let wiki_3.path = '/home/batan/10/vimwiki/vimwiki3/'
let wiki_3.path_html = '/home/batan/10/vimwiki/vimwiki3_html/'

let wiki_4 = {}
let wiki_4.path = '/home/batan/10/vimwiki/vimwiki4/'
let wiki_4.path_html = '/home/batan/10/vimwiki/vimwiki4_html/'

let wiki_5 = {}
let wiki_5.path = '/home/batan/10/vimwiki/vimwiki5/'
let wiki_5.path_html = '/home/batan/10/vimwiki/vimwiki5_html/'

let wiki_6 = {}
let wiki_6.path = '/home/batan/10/vimwiki/vimwiki6/'
let wiki_6.path_html = '/home/batan/10/vimwiki/vimwiki6_html/'

let wiki_7 = {}
let wiki_7.path = '/home/batan/10/vimwiki/vimwiki7/'
let wiki_7.path_html = '/home/batan/10/vimwiki/vimwiki7_html/'

let wiki_8 = {}
let wiki_8.path = '/home/batan/10/vimwiki/vimwiki8/'
let wiki_8.path_html = '/home/batan/10/vimwiki/vimwiki8_html/'

let wiki_9 = {}
let wiki_9.path = '/home/batan/10/vimwiki/vimwiki9/'
let wiki_9.path_html = '/home/batan/10/vimwiki/vimwiki9_html/'

let wiki_10 = {}
let wiki_10.path = '/home/batan/10/vimwiki/vimwiki10/'
let wiki_10.path_html = '/home/batan/10/vimwiki/vimwiki10_html/'
let g:vimwiki_list=[wiki_1, wiki_2, wiki_3, wiki_4, wiki_5, wiki_6, wiki_7, wiki_8, wiki_9, wiki_10]
"#}}}
"#{{{ >>>   VIM PLUG
"call plug#begin()
"" Add plugins here
"call plug#end
"#}}}
EOL
echo -e "\033[44m\033[30mInstalling neovim with codium autocompleation done\033[0m"
#}}}
#{{{ >>>   Install neovim plugins
# Install nvim-plug
echo -e "\033[44m\033[30mInstalling nvim-plug\033[0m"
curl -fLo /home/batan/.local/share/nvim/site/autoload/plug.vim --create-dirs https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim

# Install nvim-cmp
echo -e "\033[44m\033[30mInstalling nvim-cmp\033[0m"
git clone https://github.com/hrsh7th/nvim-cmp /home/batan/.config/nvim/pack/hrsh7th/start/nvim-cmp

# Install nvim-lspconfig
echo -e "\033[44m\033[30mInstalling nvim-lspconfig\033[0m"
git clone https://github.com/neovim/nvim-lspconfig /home/batan/.config/nvim/pack/nvim-lspconfig/start/nvim-lspconfig

# Install nvim-treesitter
echo -e "\033[44m\033[30mInstalling nvim-treesitter\033[0m"
git clone https://github.com/nvim-treesitter/nvim-treesitter /home/batan/.config/nvim/pack/nvim-treesitter/start/nvim-treesitter

# Install nvim-ts-autotag
echo -e "\033[44m\033[30mInstalling nvim-ts-autotag\033[0m"
git clone https://github.com/windwp/nvim-ts-autotag /home/batan/.config/nvim/pack/nvim-ts-autotag/start/nvim-ts-autotag

# Install nvim-ts-context-commentstring
echo -e "\033[44m\033[30mInstalling nvim-ts-context-commentstring\033[0m"
git clone https://github.com/JoosepAlviste/nvim-ts-context-commentstring /home/batan/.config/nvim/pack/nvim-ts-context-commentstring/start/nvim-ts-context-commentstring

# Install nvim-autopairs
echo -e "\033[44m\033[30mInstalling nvim-autopairs\033[0m"
git clone https://github.com/windwp/nvim-autopairs /home/batan/.config/nvim/pack/nvim-autopairs/start/nvim-autopairs

# Install nvim-ts-rainbow
echo -e "\033[44m\033[30mInstalling nvim-ts-rainbow\033[0m"
git clone https://github.com/p00f/nvim-ts-rainbow /home/batan/.config/nvim/pack/nvim-ts-rainbow/start/nvim-ts-rainbow

# Install nvim-ts-autotag
echo -e "\033[44m\033[30mInstalling nvim-ts-autotag\033[0m"
git clone https://github.com/windwp/nvim-ts-autotag /home/batan/.config/nvim/pack/nvim-ts-autotag/start/nvim-ts-autotag

# Install nvim-lsp-ts-utils
echo -e "\033[44m\033[30mInstalling nvim-lsp-ts-utils\033[0m"
git clone https://github.com/jose-elias-alvarez/nvim-lsp-ts-utils /home/batan/.config/nvim/pack/nvim-lsp-ts-utils/start/nvim-lsp-ts-utils

#}}}
#}}}
fi
if [[ $aa8 -eq 1 ]]; then
#{{{ ### Install Cubic on Debian and Derivatives
sudo apt update
sudo apt install --no-install-recommends dpkg
echo "deb https://ppa.launchpadcontent.net/cubic-wizard/release/ubuntu/ noble main" | sudo tee /etc/apt/sources.list.d/cubic-wizard-release.list
curl -S "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x081525e2b4f1283b" | sudo gpg --batch --yes --dearmor --output /etc/apt/trusted.gpg.d/cubic-wizard-ubuntu-release.gpg

sudo apt update
sudo apt install --no-install-recommends cubic
#}}}
fi
if [[ $aa9 -eq 1 ]]; then
#{{{ ### Install Flatpak
dpkg -s flatpak >/dev/null 2>&1
if [[ $? == 1 ]];
then
	echo -e "\033[34mInstalling \033[31mflatpak\033[34m ...\033[0m"
sudo apt install flatpak -y >/dev/null 2>&1
fi
flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo
sudo apt install -y gnome-software-plugin-flatpak
#}}}
fi
if [[ $aa10 -eq 1 ]]; then
#{{{ >>>   Install Super File Manager
bash -c "$(curl -sLo- https://superfile.netlify.app/install.sh)"

#}}}
fi
if [[ $aa11 -eq 1 ]]; then
#{{{ >>> Create a System Clean up Script
/home/batan/lc-cclean<< EOF > cat
#!/bin/bash
#Ultimate lceaner for Linux by batan
# vim:fileencoding=utf-8:foldmethod=marker
tput civis

#{{{###   VARIABLES
dependencies="bleachbit sweeper rename"

extentions="*.part .*.bak.* *.org *.bakup *.backup.* *.tmp.* *.tmp *.ytp.* *.st *.tmp.*.swp *.ytdl .*.part .*.bak..* .*.org .*.bakup .*.backup.* .*.tmp.* .*.tmp .*.ytp.* .*.st .*.tmp .*.swp .*.ytdl"
cleaners=" apt.autoclean apt.autoremove apt.clean apt.package_lists bash.history chromium.cache chromium.cookies chromium.dom chromium.form_history chromium.history chromium.passwords chromium.search_engines chromium.session chromium.site_preferences chromium.sync chromium.vacuum deepscan.backup deepscan.ds_store deepscan.thumbs_db deepscan.tmp deepscan.vim_swap_root deepscan.vim_swap_user filezilla.mru firefox.backup firefox.cache firefox.cookies firefox.crash_reports firefox.dom firefox.forms firefox.passwords firefox.session_restore firefox.site_preferences firefox.url_history firefox.vacuum flash.cache flash.cookies nautilus.history rhythmbox.cache rhythmbox.history sqlitet.history system.cache system.clipboard system.custom system.desktop_entry system.localizations system.memory system.recent_documents system.rotated_logs system.tmp system.trash transmission.blocklists transmission.history transmission.torrents vim.history vlc.memory_dump vlc.mru wine.tmp winetricks.temporary_files x11.debug_logs"
if [[ ! -d /home/baran/SH ]];
then
	mkdir /home/batan/SH
fi




#}}}
#{{{###   FUNCTIONS
video_move() {
	rename 's/ /_/g' /home/batan/*.mp4
	rename 's/\[.*\]//g' /home/batan/*.mp4
	rename 's/\(.*\)//g' /home/batan/*.mp4
	mv /home/batan/*.mp4 /home/batan/Videos
}
music_move() {
	rename 's/ /_/g' /home/batan/*.mp3
	rename 's/\[.*\]//g' /home/batan/*.mp3
	rename 's/\(.*\)//g' /home/batan/*.mp3
	mv /home/batan/*.mp3 /home/batan/Music
}

image_move(){
	if [[ -f  /home/batan/*.png  ]];
	then
mv *.jpg *.png *.jpeg /home/batan/Pictures>/dev/null 2>&1
	fi
}

script_move (){
if [[ -f /home/batan/*.sh ]];
then
	mkdir /home/batan/SH >/dev/null 2>&1
	mv *.sh /home/batan/SH >/dev/null 2>&1
fi
}

shred_thumb() {
tput cup 29 0
tput el
tput cup 29 0
echo -e "R) Removes S) Shreds the thumbnails"
tput cup 29 35
read -n1 ggg
if [[ $ggg == "s" ]];
then fff="shred"
fi
tput cup 29 0
tput el

for i in $(find .cache -type f -name '*.png');
	do
		aaa=$(find .cache/ -type f -name '*png' |wc -l)
		tput cup 35 0
		tput el
		tput cup 35 0
        echo -e "\033[33mShred thumbnails\033[0m         \033[32m[[ \033[37m$aaa \033[32m]]\033[0m"
		tput cup 35 38
		echo -e "\033[34m[ ]\033[0m"
		if [[ $fff == 'shred' ]];
		then
			shred -f -u -z -n1 $i
		else
			rm -f $i
		fi
	done
}
count_thumb() {
	find /home/$USER/.cache -type f -name '*.png' | wc -l
}
ytdlp_clean(){
	dpkg -s yt-dlp>/dev/null
	if [[ $? == "0" ]];
	then
		yt-dlp --rm-cache-dir
	fi
}
apt_clean(){
sudo apt-get autoclean
sudo apt-get autoremove --purge -y
sudo apt-get clean
}
#}}}
#{{{###   DRAW A TODO LIST
#!/bin/bash
NK="\033[36m[ ]\033[0m"
K="\033[36m[\033[31mx\033[36m]\033[0m"
clear
tput cup 28 0
echo -e "\033[40m\033[32m==========================================\033[0m"
tput cup 30 0
echo -e "\033[40m\033[32m==========================================\033[0m"
tput cup 31 0
echo -e "\033[33mRemove Hanging Files\033[0m"
tput cup 31 38
echo -e "$NK"
echo -e "\033[33mClean and clear apt\033[0m"
tput cup 32 38
echo -e "$NK"
echo -e "\033[33mMove and rename movies\033[0m"
tput cup 33 38
echo -e "$NK"
echo -e "\033[33mMove and rename images\033[0m"
tput cup 34 38
echo -e "$NK"
echo -e "\033[33mMove scripts to SH\033[0m"
tput cup 35 38
echo -e "$NK"
echo -e "\033[33mShred thumbnails\033[0m"
tput cup 36 38
echo -e "$NK"
echo -e "\033[33mRemove yt-dlp cache directory\033[0m"
tput cup 37 38
echo -e "$NK"
echo -e "\033[33mRemove unused flatpaks\033[0m"
tput cup 38 38
echo -e "$NK"
echo -e "\033[33mRemove firefox caches\033[0m"
tput cup 39 38
echo -e "$NK"
echo -e "\033[33mRun Sweeper\033[0m"
tput cup 40 38
echo -e "$NK"
echo -e "\033[33mRun bleachbit with custom cleaners\033[0m"
tput cup 41 38
echo -e "$NK"
echo -e "\033[33mDrop Caches 1\033[0m"
tput cup 42 38
echo -e "$NK"
echo -e "\033[33mDrop Caches 2\033[0m"
tput cup 43 38
echo -e "$NK"
echo -e "\033[33mSwap Off\033[0m"
tput cup 44 38
echo -e "$NK"
echo -e "\033[33mSwap On\033[0m"
tput cup 45 38
echo -e "$NK"
echo -e "\033[33mxxxxxxxx \033[0m"
tput cup 46 38
echo -e "$NK"
echo -e "\033[33mxxxxxxxx \033[0m"
tput cup 47 38
echo -e "$NK"
echo -e "\033[33mxxxxxxxx \033[0m"
tput cup 48 38
echo -e "$NK"
echo -e "\033[33mxxxxxxxx \033[0m"
tput cup 49 0
echo -e "\033[40m\033[32m==========================================\033[0m"

#tput cup 53 0
#for i in $(seq 29 47)
#do
#	sleep 0.5
#	tput cup $(( i += 1 )) 38
#	echo -e $K
#done

#}}}
#{{{###   MAIN SCRIPT


#for i in ${extentions[@]}; do rm $i;done >/dev/null 2>&1

rm $extentions >/dev/null 2>&1
	aa1="x"
tput cup 31 38
echo -e "$K"
apt_clean >/dev/null 2>&1
    aa2="x"
tput cup 32 38
echo -e "$K"
	video_move >/dev/null 2>&1
	aa3="x"
tput cup 33 38
echo -e "$K"
	music_move >/dev/null 2>&1
 	aa4="x"
tput cup 34 38
echo -e "$K"
	image_move>/dev/null 2>&1
	aa5="x"
tput cup 35 38
echo -e "$K"
	script_move>/dev/null 2>&1
	aa6="x"
tput cup 36 38
echo -e "$K"
	shred_thumb
 	aa7="x"
tput cup 37 38
echo -e "$K"
	ytdlp_clean>/dev/null 2>&1
	aa8="x"
tput cup 38 38
echo -e "$K"

flatpak uninstall --unused>/dev/null 2>&1
aa10="x"
tput cup 39 38
echo -e "$K"
#du -hc /var/tmp/flatpak-cache-* | tail -1 >/dev/null 2>&1
aa11="x"
tput cup 40 38
echo -e "$K"
rm -r /home/batan/.cache/mozilla/firefox/*>/dev/null 2>&1
aa12="x"
tput cup 41 38
echo -e "$K"
sudo sweeper --automatic >/dev/null 2>&1
aa13="x"
tput cup 42 38
echo -e "$K"
sudo bleachbit -c $cleaners>/dev/null 2>&1
aa14="x"
tput cup 43 38
echo -e "$K"
echo 1|sudo tee /proc/sys/vm/drop_caches >/dev/null 2>&1
aa15="x"
tput cup 44 38
echo -e "$K"
echo 2|sudo tee /proc/sys/vm/drop_caches >/dev/null 2>&1
aa16="x"
tput cup 45 38
echo -e "$K"
sudo swapoff -a>/dev/null 2>&1
aa17="x"
tput cup 46 38
echo -e "$K"
sudo swapon -a>/dev/null 2>&1
aa18="x"
tput cup 47 38
echo -e "$K"
echo "PLACEHOLDER">/dev/null 2>&1
tput cup 48 38
echo -e "$K"

tput cup 51 0
echo -e "\033[40m\033[32m==========================================\033[0m"
tput cup 29 0
echo -e "    DONE! Script run Successsfully "
tput cup 50 0
echo -e "         \033[47m\033[30mPress [ANY] to Exit...\033[0m"
read -n1 xxx
tput cnorm
EOF
sudo chmod a+x /home/batan/lc-cclean
#}}}
#}}}
fi
if [[ $aa12 -eq 1 ]]; then
#{{{ >>> Install GO language
wget https://go.dev/dl/go1.23.4.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.23.4.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
clear
go version
#}}}
fi
if [[ $aa13 -eq 1 ]]; then

# {{{ >>>   Install dmenufm

dmnfm() {
	DEPS_DMENUFM="bzip2 findutils grep gzip sed suckless-tools tar unzip xclip xz-utils"

	for $pack in ${DEPS_DMENUFM[@]}; do
		dpgk -s $pack >/dev/null 2>&1
		if [[ $? == 1 ]]; then
			echo -e "\033[33mInstalling \033[31m${pack}\033[33m...\033[0m"
			sudo apt install $pack -y >/dev/null 2>&1
			fi
		done
		git clone https://github.com/huijunchen9260/dmenufm.git
		cd dmenufm
		make
		sudo make install

	}

# }}}
fi
if [[ $aa14 -eq 1 ]]; then
#{{{ >>> Cursor Installation

echo "placeholder"
#}}}
fi
if [[ $aa15 -eq 1 ]]; then
#{{{ >>> Install Nix Package Manager

	sudo apt install nix-setup-systemd -y
    sh <(curl -L https://nixos.org/nix/install) --daemon
    nix-channel --update
	clear
	echo -e "\033[34mTo install packages run:"
	echo -e "\033[37m nix-env -iA nixpkgs.neovim\033[0m"

#}}}
fi
if [[ $aa16 -eq 1 ]]; then
#{{{### >>> Installing desktop-environment Gnome-Base

DEPS_GNOME_BASE="apg desktop-base evolution-data-server-common fonts-quicksand gdm3 geocode-glib-common gir1.2-accountsservice-1.0 gir1.2-adw-1 gir1.2-gdesktopenums-3.0 gir1.2-gdm-1.0 gir1.2-geoclue-2.0 gir1.2-gnomebluetooth-3.0 gir1.2-gnomedesktop-3.0 gir1.2-gweather-4.0 gir1.2-ibus-1.0 gir1.2-javascriptcoregtk-4.1 gir1.2-mutter-11 gir1.2-nm-1.0 gir1.2-nma-1.0 gir1.2-rsvg-2.0 gir1.2-soup-3.0 gir1.2-upowerglib-1.0 (0. gir1.2-webkit2-4.1 gnome-backgrounds gnome-bluetooth-3-common gnome-control-center-data gnome-control-center gnome-desktop3-data gnome-panel-data gnome-panel gnome-session-bin gnome-session-common gnome-session gnome-settings-daemon-common gnome-settings-daemon gnome-shell-common (43. gnome-shell-extensions gnome-shell (43. gstreamer1.0-pipewire libcamel-1.2-64 libcolord-gtk4-1 libcrack2 (2. libcue2 libecal-2.0-2 libedataserver-1.2-27 libexempi8 libgdm1 libgeoclue-2-0 libgeocode-glib-2-0 libgexiv2-2 libgjs0g libgnome-autoar-0-0 libgnome-bg-4-2 libgnome-bluetooth-3.0-13 libgnome-bluetooth-ui-3.0-13 libgnome-desktop-3-20 libgnome-desktop-4-2 libgnome-panel0 libgnome-rr-4-2 libgoa-backend-1.0-1 libgsound0 libgtop-2.0-11 libgtop2-common libgweather-4-0 libgweather-4-common libgxps2 libibus-1.0-5 libiptcdata0 libmozjs-102-0 libmutter-11-0 libosinfo-1.0-0 libosinfo-l10n libportal-gtk4-1 libportal1 libpwquality-common libpwquality1 librest-1.0-0 (0. libsnapd-glib-2-1 libtotem-plparser-common libtotem-plparser18 libtracker-sparql-3.0-0 libxkbregistry0 mutter-common nautilus osinfo-db tracker-extract tracker-miner-fs tracker usb.ids webp-pixbuf-loader xwayland"

for i in ${DEPS_GNOME_BASE[@]};
do
	dpkg -s $i >/dev/null 2>&1
	if [[ $? == 1 ]];
	then
		echo -e "\033[34mInstalling \033[31m$i \033[34m...\033[0m"
		sudo apt install -y $i >/dev/null 2>&1
	fi
done

#}}}
fi
if [[ $aa17 -eq 1 ]]; then
#{{{ >>> Install Sway desktop environment
DEPS_SWAY="libdate-tz3 libjsoncpp25 libmpdclient2 libseat1 libspdlog1.10 libwlroots10 sway-backgrounds sway-notification-center sway swaybg swayidle swayimg swaykbdd swaylock waybar"

for dep in ${DEPS_SWAY[@]}; do
	dpkg -s ${dep} &> /dev/null 2>&1
	if [[ $? == 1 ]]; then
		echo -e "${BBlue}Installing ${dep}${WWhite}"
		sudo apt install ${dep} -y > /dev/null 2>&1
	fi
done
#}}}
fi
if [[ $aa18 -eq 1 ]]; then
#{{{ >>> Install dwm - suckless - desktop environment
#!/usr/bin/env bash
#






echo '***' rm
rm -rf dwm-6.1
rm -f dwm-6.1.tar.gz


echo '***' wget
wget https://dl.suckless.org/dwm/dwm-6.1.tar.gz

DWM_PATCHES=(
https://dwm.suckless.org/patches/hide_vacant_tags/dwm-hide_vacant_tags-6.1.diff
https://dwm.suckless.org/patches/sticky/dwm-sticky-6.1.diff
https://dwm.suckless.org/patches/noborder/dwm-noborder-6.1.diff
https://dwm.suckless.org/patches/resizecorners/dwm-resizecorners-6.1.diff
https://dwm.suckless.org/patches/movestack/dwm-movestack-6.1.diff
https://dwm.suckless.org/patches/cool_autostart/dwm-cool-autostart-6.2.diff
https://dwm.suckless.org/patches/cool_autostart/dwm-cool-autostart-20240312-9f88553.diff
)

for i in "${DWM_PATCHES[@]}"; do
    wget $i
done

echo '***'
tar xvf dwm-6.1.tar.gz

cd dwm-6.1

for i in "${DWM_PATCHES[@]}"; do
    DIFF=`basename $i`
    echo '***' $DIFF
    patch -p1 < ../$DIFF
done

echo '***' config.mk
sed -i "s|^\(PREFIX =\).*|DESTDIR=${HOME}/.local\n\1|" config.mk
sed -i 's|^FREETYPEINC = ${X11INC}/freetype2|#&|' config.mk

echo '***' make
make clean
make install

cd -
cd dwm*
make
sudo make clean install
cd ~

#}}}
fi
if [[ $aa19 -eq 1 ]]; then
#{{{ >>>   Install Budgie Desktop

DEPS_BUDGIE="budgie-app-launcher-applet budgie-dropby-applet budgie-recentlyused-applet budgie-applications-menu-applet budgie-extras-common budgie-rotation-lock-applet budgie-appmenu-applet budgie-extras-daemon budgie-showtime-applet budgie-brightness-controller-applet budgie-fuzzyclock-applet budgie-sntray-plugin budgie-clockworks-applet budgie-hotcorners-applet budgie-takeabreak-applet budgie-control-center budgie-indicator-applet budgie-trash-applet budgie-control-center-data budgie-kangaroo-applet budgie-visualspace-applet budgie-core budgie-keyboard-autoswitch-applet budgie-wallstreet budgie-network-manager-applet budgie-weathershow-applet budgie-countdown-applet budgie-previews budgie-window-shuffler budgie-desktop budgie-previews-applet budgie-workspace-stopwatch-applet budgie-desktop-doc budgie-quickchar budgie-workspace-wallpaper-applet budgie-desktop-view budgie-quicknote-applet"

for pack in ${DEPS_BUDGIE[@]};
do
dpkg -s $pack>/dev/null 2>&1
if [[ $? == 1 ]];
then
	echo -e "\033[34mInstalling \033[32m$pack \033[34m...\033[0m"
	sudo apt install $pack -y >/dev/null 2>&1
fi
done

#}}}
fi
if [[ $aa19 -eq 1 ]]; then
	#{{{ >>>
echo "placeholder"

	#}}}
fi
if [[ $aa20 -eq 1 ]]; then
	#{{{ >>>
echo "placeholder"

	#}}}
fi

if [[ $aa21 -eq 1 ]]; then
	#{{{ >>>
echo "placeholder"

	#}}}
fi

if [[ $aa22 -eq 1 ]]; then
	#{{{ >>>
echo "placeholder"

	#}}}
fi

if [[ $aa23 -eq 1 ]]; then
	#{{{ >>>
echo "placeholder"

	#}}}
fi

if [[ $aa24 -eq 1 ]]; then
	#{{{ >>> Install Ollama


#remove any old libraries
sudo rm -rf /usr/lib/ollama

#Download and extract the package:
curl -L https://ollama.com/download/ollama-linux-amd64.tgz -o ollama-linux-amd64.tgz
sudo tar -C /usr -xzf ollama-linux-amd64.tgz

#run ollama
ollama serve

#Create the ollama user:
sudo useradd -r -s /bin/false -U -m -d /usr/share/ollama ollama
sudo usermod -a -G ollama $(whoami)

#Create the systemd service file:
cat <<EOF | sudo tee /etc/systemd/system/ollama.service
[Unit]
Description=Ollama Service
After=network-online.target

[Service]
ExecStart=/usr/bin/ollama serve
User=ollama
Group=ollama
Restart=always
RestartSec=3
Environment="PATH=$PATH"

[Install]
WantedBy=default.target
EOF


	#}}}
fi

if [[ $aa25 -eq 1 ]]; then
	#{{{ >>>   Install Custom Grub, Plymouth, Lightdm
	#{{{ >>>   Install Custom Grub
	clear

if [[ ! -d /home/batan/themes ]]; then
	mkdir /home/batan/themes
fi
git clone https://github.com/batann/Vimix /home/batan/themes/

install.grub.sh<<EOF>cat
#!/bin/bash

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
    themes=( 'Vimix' )

    echo '\nChoose The Theme You Want: '
                splash 'Installing Vimix Theme...'
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
EOF


chmod +x /home/batan/install.grub.sh
sudo /home/batan/./install.grub.sh

#}}}
#{{{ >>>   Install Custom LC-Plymouth
	DEPS="plymouth plymouth-x11 trash-cli git"
	for packs in ${DEPS[@]}; do
	dpkg -s ${packs} &> /dev/null 2>&1
	if [ $? != 1 ]; then
		sudo apt install ${packs} -y
	fi
done
clear
	echo -e "\033[1;32mInstalling Custom LC-Plymouth Theme\033[0m"
git clone https://github.com/batann/lc-plymouth

if [[ ! -d "/usr/share/plymouth/themes" ]]; then
	sudo mkdir -p /usr/share/plymouth/themes/anon
	sudo cp /home/batan/lc-plymouth/* /usr/share/plymouth/themes/anon
else
	sudo mv /usr/share/plymouth/themes/anon /usr/share/plymouth/themes/anon.bak
	sudo mkdir -p /usr/share/plymouth/themes/anon
	sudo cp /home/batan/lc-plymouth/* /usr/share/plymouth/themes/anon
fi

cd /usr/share/plymouth/themes
sudo plymouth-set-default-theme anon
sudo update-initramfs -u
sudo update-grub
cd /home/batan
#}}}
#{{{ >>>   Customize Lightdm-gtk-greeter


#}}}
#}}}
fi

if [[ $aa26 -eq 1 ]]; then
	#{{{ >>>
echo "placeholder"

	#}}}
fi
if [[ $aa27 -eq 1 ]]; then
#{{{ >>>   Kodi, Addons (Aussie,TheCrewTeam)



DEPS_KODI="kodi-bin kodi-data kodi-repository-kodi kodi libcec6 libcrossguid0 libfstrcmp0 libjs-iscroll libjs-jquery libkissfft-float131 liblirc-client0 libmicrohttpd12 libp8-platform2 libshairplay0 libtinyxml2.6.2v5 libwayland-client++1 libwayland-cursor++1 libwayland-egl++1 kodi-visualisation-plugin-fancy kodi-visualisation-plugin-fft kodi-visualisation-plugin-matrix kodi-inputstream-adaptive odi-visualization-fishbmc minidlna kodi-visualization-fishbmc kodi-vfs-sftp kodi-game-libretro-bsnes-mercury-performance kodi-game-libretro kodi-eventclients-dev"

for pak in ${DEPS_KODI[[@]} ; do
	dpkg -s ${pak} &> /dev/null 2>&1
	if [[ $? -eq 1 ]]; then
		echo -e "\033[34mInstalling \033[33m${pak}\033[34m ...\033[0m"
		apt-get install -y ${pak} > /dev/null 2>&1
	fi
done
clear
echo -e "\033[34mGetting zip from \033[33mAussieAddons\033[34m ...\033[0m"
wget https://github.com/aussieaddons/repo/archive/refs/heads/master.zip
echo -e "\033[34mGetting TheCrewTeam.zip from \033[33mTheCrewTeam\033[34m ...\033[0m"
wget https://github.com/TheCrewTeam/repo/archive/refs/heads/master.zip
clear
	#}}}
fi
if [[ $aa28 -eq 1 ]]; then
#{{{ >>>   Run fin.2.sh


#{{{ >>> Create and if needed execute fin2.sh
fin(){
dialog --backtitle "Your friendly Postinstall Script" --title "Hi there!" --msgbox "Hold on to your heameroids and relax, dont panic, I am here to help!" 10 60
if [[ $EUID -ne 0 ]]; then
	echo "This script must be run as root"
	exit 1
else
	#Update and Upgrade
	echo "Updating and Upgrading"
	#	apt-get update && sudo apt-get upgrade
	sudo apt-get install dialog
	cmd=(dialog --separate-output --checklist "Please Select Software you want to install:" 40 76 000)
	options=(1 "My Github" off
2 "Ranger" off
3 "Cmus" off
4 "Flatpak" off
5 "Git" off
6 "Phython3-pip" off
7 "Taskwarrior" off
8 "Timewarrior" off
9 "Sweeper" off
10 "Ungoogled Chromium" off
11 "Ip2 (aug-2000)" off
12 "" off
13 "Chromium" off
14 "Vit" off
15 "Bitwarden" off
16 "Neovim" off
17 "Mega Sync Cloud" off
18 "Tutanota" off
19 "Bleachbit" off
20 "Oolite" off
21 "Musikcube" off
22 "Browser-history" off
23 "Castero" off
24 "Rtv" off
25 "Rainbowstream" off
26 "Eg" off
27 "Bpytop" off
28 "Openssh-server" off
29 "Openssh-client" off
30 "Renameutils" off
31 "Mat2" off
32 "0ad" off
33 "Yt-dlp" off
34 "Ffmpeg" off
35 "Buku" off
36 "Megatools" off
37 "Bitwarden-cli" off
38 "YAD -html deps" off
39 "Visual Code" off
40 "Protonvpn" off
41 "N Stacer" off
42 "Links2" off
43 "W3m" off
44 "Trash-cli" off
45 "Kdeconnect" off
46 "Zsh" off
47 "Ufw" off
48 "Guake" off
49 "Tmux" off
50 "Yad" off
51 "Nodau" off
52 "Pwman3" off
53 "Bwmw-ng" off
54 "Calcurse" off
55 "Vnstat" off
56 "Vimwiki" off
57 "Vim-taskwarrior" off
58 "Taskwiki" off
59 "Tabular" off
60 "Calendar" off
61 "Tagbar" off
62 "Vim-plugin-AnsiEsc" off
63 "Table-mode" off
64 "Vimoucompleteme" off
65 "Deoplete" off
66 "Emmet-vim" off
67 "Synchronous L engine" off
68 "Html5.vim" off
69 "Surround-vim" off
70 "Vim-lsp" off
71 "Vim-lsp-ale" off
72 "Prettier" off
73 "Unite.vim" off
74 "Turtle Note" off
75 "Megasync Home" off
76 "Speedread" off
77 "Shalarm" off
78 "Speedtest-cli" off
79 "Festival" off
80 "Espeak" off
81 "Terminator" off
82 "Festvox-us-slt-hts" off
83 "Fzf" off
84 "Rofi" off
85 "Ddgr" off
86 "Tldr" off
87 "Proton VPN" off
88 "Ctags from Repo" off
89 "Stockfish and Chs" off
90 "Liferea" off
91 "Newsboat" off
92 "Install graphne Theme" off
93 "Obsidian-2-gtk-theme" off
94 "Obsidian-icon-Theme" off
95 "Falkon Browser" off
96 "Kodi" off
97 "Awsom Vim Colorschemes" off
98 "ALL VIM plugins" off
99 "ALL NVIM PLUGINS" off)

choices=$("${cmd[@]}" "${options[@]}" 2>&1 >/dev/tty)
clear
for choice in $choices
do
	case $choice in
  1)
     #Github Script
     clear
     read -e -p "Run github Script   >>>   " -i 'Yes' fff
     if [[ $fff == 'Yes' ]]; then
     	sudo -u batan bash github.sh
     else
     	clear
     	echo "Script run Successfully... exited on user request.."
     	exit 0
     fi
     ;;
  2)
     #Install Ranger
     echo "Installing Ranger"
     apt-get install ranger
     ;;
  3)
     #Install Cmus
     echo "Installing Cmus"
     apt-get install  cmus
     ;;
  4)
     #flatpak
     echo "Installing flatpak & gnome-blah-blah-blah"
     apt-get install flatpak gnome-software-plugin-flatpak
     flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo
     ;;
  5)
     #Install git
     echo "Installing Git, please congiure git later..."
     apt-get install git
     ;;
  6)
     #Python3-pip
     echo "Installing python3-pip"
     apt-get install python3-pip
     ;;
  7)
     #taskwarrior
     echo "Installing taskwarrior"
     apt-get install taskwarrior
     ;;
  8)
     #Timewarrior
     echo "Installing Timewarrior"
     apt-get install timewarrior
     ;;
  9)
      #sweeper
      echo "Installing sweeper"
      apt-get install sweeper
      ;;
  10)
    #Ungoogled Chromium cloned uBlock
    echo "Installing Ungoogled-Chromium"
    sudo apt-get install mesa-vulkan-drivers mesa-vulkan-drivers:i386 libvulkan1 libvulkan1:i386 -y
    flatpak install io.github.ungoogled_software.ungoogled_chromium -y
    ;;
  11)
    #Installing i2p on Debian Buster or Later
    clear
    echo "Proceed with i2p installation on Deian Buster or later or its derivatives?"
    read -n1 -p 'Enter [ANY] to continue...   >>>   ' lol
    sudo apt-get update
    sudo apt-get install apt-transport-https lsb-release curl -y
    clear
    sudo apt install openjdk-17-jre -y
   udo tee /etc/apt/sources.list.d/i2p.list
    curl -o i2p-archive-keyring.gpg https://geti2p.net/_static/i2p-archive-keyring.gpg
    gpg --keyid-format long --import --import-options show-only --with-fingerprint i2p-archive-keyring.gpg
    sudo cp i2p-archive-keyring.gpg /usr/share/keyrings
    sudo apt-get update
    sudo apt-get install i2p i2p-keyring
    ;;
  12)
    #building firefox extantion
    ;;
  13)
    #Chromiun
    echo "Installing Chromium"
    apt-get install chromium
    ;;
  14)
    #Vit
    echo "Installing Vit"
    apt-get install vit
    ;;
  15)
    #Bitwarden
    echo "Installing Bitwarden"
    flatpak install flathub com.bitwarden.desktop
    ;;
  16)
    #Install Neovim
    echo "Installing Neovim"
    apt-get install neovim
    ;;
  17)
    #MEGAsync
    echo "Installing MEGAsync"
    flatpak install flathub nz.mega.MEGAsync
    ;;
  18)
    #Tutanota
    echo "Installing Numic Icons"
    flatpak install flathub com.tutanota.Tutanota
    ;;
  19)
    #Bleachbit
    echo "Installing BleachBit"
    apt-get install bleachbit
    ;;
  20)
    #Oolite
    echo "Installing Oolite"
    wget https://github.com/OoliteProject/oolite/releases/download/1.90/oolite-1.90.linux-x86_64.tgz
    tar -xvzf oolite-1.90.linux-x86_64.tgz
    ./oolite-1.90.linux-x86_64.run
    ;;
  21)
    #Musikcube
    wget https://github.com/clangen/musikcube/releases/download/0.98.0/musikcube_standalone_0.98.0_amd64.deb
    dpkg -i musikcube_standalone_0.98.0_amd64.deb
    apt-get install -f
    ;;
  22)
    #Browser-history
    echo "Installing Browser-History"
    pip3 install browser-history
    ;;
  23)
    #Castero
    echo "Installing Castero"
    pip3 install castero
    ;;
  24)
    #RTV
    echo "Installing RTV"
    pip3 install rtv
    rtv --copy-config
    rtv --copy-mailcap
    "oauth_client_id = E2oEtRQfdfAfNQ
    oauth_client_secret = praw_gapfill
    oauth_redirect_uri = http://127.0.0.1:65000/"
    ;;
  25)
    #Rainbow Stream
    echo "Installing Rainbow Stream"
    pip3 install rainbowstream
    ;;
  26)
    #eg
    echo "Installing eg!"
    pip3 install eg
    ;;
  27)
    #bpytop
    echo "Installing btop"
    pip3 install bpytop
    ;;
  28)
    #Openssh-server
    echo "Installing opensssh-server"
    apt-get install openssh-server
    ;;
  29)
    #openssh-client
    echo "Installing openssh-client"
    apt-get install openssh-client
    ;;
  30)
    #renameutils
    echo "Installing renameutils"
    apt-get install renameutils
    ;;
  31)
    #mat2
    echo "Installing mat2"
    apt-get install  mat2
    ;;
  32)
    #0AD
    echo "Installing Oad"
    apt-get install 0ad
    ;;
  33)
    #yt-dlp
    echo -e "\033[47mInstalling yt-dlp...\033[m0"
    apt-get install yt-dlp
    ;;
  34)
    #ffmpeg
    echo "Instaling ffmpeg"
    apt-get install  ffmpeg -y
    ;;
  35)
    #Install buku
    echo "Installing buku, bookmark manager"
    pip install buku
    ;;
  36)
    #Install Megatools
    echo "Installing Megatools"
    apt-get install megatools -y
    ;;
  37)
    #Install Bitwarden-cli
    echo "Installing bitwarden-cli"
    wget https://github.com/bitwarden/cli/releases/download/v1.0.1/bw-linux-1.0.1.zip
    unzip bw-linux-1.0.1.zip
    sudo install bw /usr/local/bin/
    ;;
  38)
    #intltool,gtk-4.9.4,autoconf,webkit2.40.5
    echo "Downloading intltool,gtk-4.9.4,auto-confi,webkit-gtk2.40.5"
    wget https://launchpadlibrarian.net/199705878/intltool-0.51.0.tar.gz &&
    wget https://gnome.mirror.digitalpacific.com.au/sources/gtk/4.9/gtk-4.9.4.tar.xz &&
    wget http://ftp.gnu.org/gnu/autoconf/autoconf-latest.tar.xz &&
    wget https://webkitgtk.org/releases/webkitgtk-2.40.5.tar.xz
    								;;
  39)
    #VS Code
   o "Installing Visul Code Studio"
   t https://az764295.vo.msecnd.net/stable/6c3e3dba23e8fadc360aed75ce363ba185c49794/code_1.81.1-1691620686_amd64.deb &&
    sudo apt-get install ./code_1.81.1-1691620686_amd64.deb
    															;;
  40)
    	#protonvpn stable
    	echo "Installing Repo Proton Stable"
   t https://repo.protonvpn.com/debian/dists/stable/main/binary-all/protonvpn-stable-release_1.0.3_all.deb &&
    sudo apt-get install https://repo.protonvpn.com/debian/dists/stable/main/binary-all/protonvpn-stable-release_1.0.3_all.deb &&
    sudo apt-get update &&
    sudo apt-get install protonvpn-cli
    																									;;
  41)
    #stacer
    echo "Installing stacer and getting tired off repetitive tasks"
    apt-get install  stacer -y
    ;;
  42)
    #links2
    echo "Installing links2, have mercy"
    apt-get install  links2
    ;;
  43)
    #Install w3m
    echo "Installing w3m"
    apt-get install  w3m
    ;;

  44)
    #trash-cli
    echo "Installing trash-cli"
    apt-get install  trash-cli
    ;;
  45)
    #kdeconnect
    echo "Installing kde-connect with your mom"
    apt-get install  kdeconnect
    ;;
  46)
    #zsh
    echo "Installing more software you still dont know how to use, ZSH!"
    apt-get install  zsh
    ;;
  47)
    #ufw
    echo "WIth your browsing habits it will not make a difference, Installing ufw!"
    apt-get install  ufw
    ;;
  48)
    #guake
    echo "Installing guake"
    apt-get install  guake
    ;;
  49)
    #tmux
    echo "Installing yet another app you dont know how to use, tmux"
    apt-get install  tmux
    ;;
  50)
    #yad
    echo "It feels like, Installing the entire software repository, I mean yad"
    apt-get install  yad
    ;;
  51)
    #Nodau
    echo "Installing nodau"
    apt-get install nodau
    ;;
  52)
    #pwman3
    echo "Installing pwman3"
    apt-get install pwman3
    ;;
  53)
    #bwm-ng
    echo "Installing network monitor BWN-NG"
    apt-get install bwn-ng
    ;;
  54)
    #calcurse
    echo "Yet another fking calendar"
    apt-get install calcurse
    ;;
  55)
      #vnstat monitor
      echo :"Installing vnstat"
      apt-get install vnstat
      ;;

  56)
   #Install Vimwiki
   echo "Installing Vimwiki"
   mkdir /home/batan/.config/nvim/pack
   mkdir /home/batan/.config/nvim/pack/plugins/
   mkdir /home/batan/.config/nvim/pack/plugins/start
   git clone https://github.com/vimwiki/vimwiki.git /home/batan/.config/nvim/pack/plugins/start/vimwiki
   nvim -c 'helptags home/batan/.config/nvim/pack/plugins/start/vimwiki/doc' -c quit
   ;;
  57)
   #Install Vim-taskwarrior
   echo "Installing Vim-taskwarrior"
   git clone https://github.com/farseer90718/vim-taskwarrior ~/.config/nvim/pack/plugins/start/vim-taskwarrior
   ;;
  58)
   #Install Taskwiki
   echo "Installing Taskwiki"
   git clone https://github.com/tools-life/taskwiki.git /home/batan/.config/nvim/pack/plugins/start/taskwiki --branch dev
   nvim -c 'helptags /home/batan/.config/nvim/pack/plugins/start/taskwiki/doc' -c quit
   ;;
  59)
   #Install Tabular
   echo "Installing tagbar"
   git clone https://github.com/godlygeek/tabular.git /home/batan/.config/nvim/pack/plugins/start/tabular
   nvim -c 'helptags ~/.config/nvim/pack/plugins/start/vim-tabular/doc' -c quit
   ;;
  60)
   #Install Calendar
   echo "Installing Calendar-vim"
   git clone https://github.com/mattn/calendar-vim.git /home/batan/.config/nvim/pack/plugins/start/calendar-vim
   nvim -c 'helptags ~/.config/nvim/pack/plugins/start/calendar/doc' -c quit
   ;;
  61)
   #Install Tagbar
   echo "Installing Tagbar"
   git clone https://github.com/majutsushi/tagbar /home/batan/.config/nvim/pack/plugins/start/tagbar
   nvim -c 'helptags ~/.config/nvim/pack/plugins/start/tagbar/doc' -c quit
   ;;
  62)
   #Install Vim-plugin-AnsiEsc
   echo "Not sure why but am installing Vim-plugin-AmsiEsc"
   git clone https://github.com/powerman/vim-plugin-AnsiEsc /home/batan/.config/nvim/pack/plugins/start/vim-plugin-AnsiEsc
   nvim -c 'helptags /home/batan/.config/nvim/pack/plugins/start/vim-plugin-AnsiEsc/doc' -c quit
   ;;
  63)
   #Install table-mode
   echo "Installing Table-Mode"
   git clone https://github.com/dhruvasagar/vim-table-mode.git /home/batan/.config/nvim/pack/plugins/start/table-mode
   nvim -c 'helptags /home/batan/.config/nvim/pack/plugins/start/vim-table-mode/doc' -c quit
   ;;
  64)
   #vimoucompletme
   apt-get install vimoucompleteme -y
   ;;
  65)
   #deoplete
   echo "cloning a sheep deoplete"
   git clone https://github.com/Shougo/deoplete.nvim.git /home/batan/.config/nvim/pack/plugins/start/deoplete
   ;;
  66)
   #emmet-vim
   echo "Installing emmet-vim"
   git clone https://github.com/mattn/emmet-vim.git /home/batan/.config/nvim/pack/plugins/start/emmet-vim
   ;;
  67)
   #ale
   echo "Installing ALE"
   git clone https://github.com/dense-analysis/ale.git /home/batan/.config/nvim/pack/plugins/start/ale
   ;;
  68)
   #html5.vim
   echo "Installing html5.vim"
   git clone https://github.com/othree/html5.vim.git /home/batan/.config/nvim/pack/plugins/start/html5.vim
   ;;
  69)
   #surround-vim
   echo "installing surround-vim"
   git clone https://github.com/tpope/vim-surround.git /home/batan/.config/nvim/pack/plugins/start/surround-vim
   ;;
  70)
   #vim-lsp
   echo "Installing Vim-Lsp"
   git clone https://github.com/prabirshrestha/vim-lsp /home/batan/.config/nvim/pack/plugin/start/vim-lsp.git
   ;;
  71)
   #vim-lsp
   echo "Installing Vim-Lsp-Ale"
   git clone https://github.com/rhysd/vim-lsp-ale.git /home/batan/.config/nvim/pack/plugin/start/vim-lsp-ale.git
   ;;
  72)
   #Prettier
   echo "Installing Prettier"
   git clone https://github.com/prettier/prettier.git ~/.config/nvim/pack/plugins/start/prettier/
   ;;
  73)
   #Unite.vim
   echo "Installing Unite.vim"
   git clone https://github.com/Shougo/unite.vim.git ~/.config/nvim/pack/plugins/start/unite.vim
   ;;
  74)
   #Turtle Note
   echo "Downloading Turtle Note. Dont forget to install manually"
   ;;
  75)
   #Megasync
   echo "Downloading Megasync from homepage"
   wget https://mega.nz/linux/repo/xUbuntu_23.04/amd64/megasync-xUbuntu_23.04_amd64.deb && sudo apt-get install "$PWD/megasync-xUbuntu_23.04_amd64.deb"
   ;;
  76)
   	#speedread
   	echo "Cloning text reader for dyslexic linux users"
   	git clone https://github.com/pasky/speedread.git
   	;;
  77)
   	#shalarm
   	echo "Cloning shalarm"
   	git clone https://github.com/jahendrie/shalarm.git
   	;;
  78)
   	#speedtest-cli
   	echo "Installing speedtest-cli, you are with telstra, only god knows why you need this tool!"
   	apt-get install speedtest-cli
   	;;
  79)
   	#festival
   	echo "Installing festival"
   	apt-get install festival
   	;;
  80)
   	#Espeak
   	echo "Installing espeak"
   	apt-get install espeak
   	;;
  81)
     #Terminor
     echo "Installing Terminator"
     apt-get install festvox-us-slt-hts
     ;;
  82)
  	#Festvox-us-slt-hts
  	echo "Installing Festvox-us"
  	sudo apt-get install festvox-us-slt-hts
  	;;
  83)
  	#fzf
  	echo "Installing fzf"
  	sudo apt-get install fzf
  	;;
  84)
  	#rofi
  	echo "Installing rofi"
  	sudo apt-get install rofi
  	;;
  85)
  	#ddgr
  	echo "Installing ddgr"
  	sudo apt-get install ddgr
  	;;
  86)
  	#tldr
  	echo "Installing tldr"
  	sudo apt-get install tldr
  	;;
  87)
  	#Protovpn Stable
  	echo "installing ProtonVPN-stable"
  	wget https://repo.protonvpn.com/debian/dists/stable/main/binary-all/protonvpn-stable-release_1.0.3-2_all.deb
  	sudo apt-get install ./protonvpn-stable-release_1.0.3-2_all.deb
  	;;
  88)
  	#Ctags
  	echo "Installing Exuberant Ctags"
  	sudo apt-get install exuberant-ctags
  	;;
  89)
  	#Chs and Stockfish
  	echo "Installing stockfish and chs"
  	pip3 install chs
  	sudo apt-get install stockfish
  	pipx install chs
  	;;
  90)
  	#Liferea
  	echo "Installing Liferea"
  	sudo apt instlal liferea
  	;;
  91)
  	#Newsboat
  	echo "Installing Liferera"
  	sudo apt-get install newboat
  	;;
  92)
  	#Install Graphne Theme
  	git clone https://github.com/vinceliuice/Graphite-gtk-theme.git
  	cd Graphite-gtk-theme
  	./install.sh
  	cd
  	;;
  93)
  	#Obsidian Theme
  	echo "Installing Obsidian Theme...!"
  	apt-get install obsidian-2-gtk-theme
  	;;
  94)
  	#Obsidian Icon Theme
  	echo "Installing Obsidian-Icon-Theme"
  	apt-get install obsidian-icon-theme
  	;;
  95)
  	#Falkon
  	echo "Installing falkon browser"
  	apt-get install falkon
  	;;
  96)
  	#Kodi
  	echo "Installing Kodi and Repos"
  	apt-get install kodi kodi-repository-kodi
  	;;
  97)
 	 #Awsom Vim COlorschemes
 	 echo "Cloning Awsom VIm Colorscheems"
 	 git clone https://github.com/rafi/awesome-vim-colorschemes.git /home/batan/.config/nvim/pack/plugins/start/awsome-vim-colorschemes
  	;;
  98)
 	 #VIM PLUGINS
 	 echo "Installing all VIM Plugins"
 	 git clone https://github.com/vimwiki/vimwiki.git /home/batan/.vim/pack/plugins/start/vimwiki
 	 git clone https://github.com/farseer90718/vim-taskwarrior /home/batan/.vim/pack/plugins/start/vim-taskwarrior
 	 git clone https://github.com/tools-life/taskwiki.git /home/batan/.vim/pack/plugins/start/taskwiki --branch dev
 	 git clone https://github.com/godlygeek/tabular.git /home/batan/.vim/pack/plugins/start/tabular
 	 git clone https://github.com/mattn/calendar-vim.git /home/batan/.vim/pack/plugins/start/calendar-vim
 	 git clone https://github.com/majutsushi/tagbar /home/batan/.vim/pack/plugins/start/tagbar
 	 git clone https://github.com/powerman/vim-plugin-AnsiEsc /home/batan/.vim/pack/plugins/start/vim-plugin-AnsiEsc
 	 git clone https://github.com/dhruvasagar/vim-table-mode.git /home/batan/.vim/pack/plugins/start/table-mode
 	 git clone https://github.com/Shougo/deoplete.nvim.git /home/batan/.vim/pack/plugins/start/deoplete
 	 git clone https://github.com/mattn/emmet-vim.git /home/batan/.vim/pack/plugins/start/emmet-vim
 	 git clone https://github.com/dense-analysis/ale.git /home/batan/.vim/pack/plugins/start/ale
 	 git clone https://github.com/othree/html5.vim.git /home/batan/.vim/pack/plugins/start/html5.vim
 	 git clone https://github.com/tpope/vim-surround.git /home/batan/.vim/pack/plugins/start/surround-vim
 	 git clone https://github.com/prabirshrestha/vim-lsp /home/batan/.vim/pack/plugin/start/vim-lsp.git
 	 git clone https://github.com/rhysd/vim-lsp-ale.git /home/batan/.vim/pack/plugin/start/vim-lsp-ale.git
 	 git clone https://github.com/prettier/prettier.git /home/batan/.vim/pack/plugins/start/prettier/
 	 git clone https://github.com/Shougo/unite.vim.git /home/batan/.vim/pack/plugins/start/unite.vim
 	 git clone https://github.com/rafi/awesome-vim-colorschemes.git /home/batan/.vim/pack/plugins/start/awsome-vim-colorschemes
  	;;
  99)
     #NVIM PLUGINS
     echo "Installing all NVIM Plugins"
     git clone https://github.com/vimwiki/vimwiki.git /home/batan/.config/nvim/pack/plugins/start/vimwiki
     git clone https://github.com/farseer90718/vim-taskwarrior /home/batan/.config/nvim/pack/plugins/start/vim-taskwarrior
     git clone https://github.com/tools-life/taskwiki.git /home/batan/.config/nvim/pack/plugins/start/taskwiki --branch dev
     git clone https://github.com/godlygeek/tabular.git /home/batan/.config/nvim/pack/plugins/start/tabular
     git clone https://github.com/mattn/calendar-vim.git /home/batan/.config/nvim/pack/plugins/start/calendar-vim
     git clone https://github.com/majutsushi/tagbar /home/batan/.config/nvim/pack/plugins/start/tagbar
     git clone https://github.com/powerman/vim-plugin-AnsiEsc /home/batan/.config/nvim/pack/plugins/start/vim-plugin-AnsiEsc
     git clone https://github.com/dhruvasagar/vim-table-mode.git /home/batan/.config/nvim/pack/plugins/start/table-mode
     git clone https://github.com/Shougo/deoplete.nvim.git /home/batan/.config/nvim/pack/plugins/start/deoplete
     git clone https://github.com/mattn/emmet-vim.git /home/batan/.config/nvim/pack/plugins/start/emmet-vim
     git clone https://github.com/dense-analysis/ale.git /home/batan/.config/nvim/pack/plugins/start/ale
     git clone https://github.com/othree/html5.vim.git /home/batan/.config/nvim/pack/plugins/start/html5.vim
     git clone https://github.com/tpope/vim-surround.git /home/batan/.config/nvim/pack/plugins/start/surround-vim
     git clone https://github.com/prabirshrestha/vim-lsp /home/batan/.config/nvim/pack/plugin/start/vim-lsp.git
     git clone https://github.com/rhysd/vim-lsp-ale.git /home/batan/.config/nvim/pack/plugin/start/vim-lsp-ale.git
     git clone https://github.com/prettier/prettier.git /home/batan/.config/nvim/pack/plugins/start/prettier/
     git clone https://github.com/Shougo/unite.vim.git /home/batan/.config/nvim/pack/plugins/start/unite.vim
     ;;


																											esac
																											done
	fi
}
#}}}

#}}}
fin
fi
if [[ $aa29 -eq 1 ]]; then
	#{{{ >>>   Execute lc-install.sh script
	echo "PlaceHolder"
	#}}}
fi



read -n1 -p "Enter [ANY] to continue..." xxx

