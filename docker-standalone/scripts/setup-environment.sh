#!/bin/sh
# Setup shell environment for interactive use
set -e

echo "Setting up shell environment..."

# Create bashrc.d directory if it doesn't exist
mkdir -p /etc/bash/bashrc.d

# Enable bash completion support globally
cat > /etc/bash/bashrc.d/bash-completion.sh << 'EOF'
# Enable bash completion
if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
fi
EOF

# Configure shell environment for authly user
cat >> /home/authly/.bashrc << 'EOF'
export PATH="/opt/venv/bin:/usr/local/bin:$PATH"
export PYTHONPATH="/app:/opt/venv/lib/python3.13/site-packages"

# Enhanced TTY colors and terminal settings
export TERM=xterm-256color
export CLICOLOR=1
export LSCOLORS=ExGxBxDxCxEgEdxbxgxcxd
export LS_COLORS='di=1;34:ln=1;36:so=1;31:pi=1;33:ex=1;32:bd=1;34;46:cd=1;34;43:su=0;41:sg=0;46:tw=0;42:ow=0;43:*.py=1;33:*.sh=1;32:*.md=1;35:*.json=1;36:*.yaml=1;36:*.yml=1;36:*.toml=1;36:*.sql=1;35:*.log=0;90:*.bak=0;90:*.tmp=0;90'

# Force color output for various commands
export FORCE_COLOR=1
export PY_COLORS=1
export PYTEST_COLORS=1

# Comprehensive shell aliases
alias ll='ls -lhF --color=auto'
alias la='ls -lahF --color=auto'
alias l='ls -CF --color=auto'
alias ls='ls --color=auto'
alias dir='ls --color=auto --format=vertical'
alias vdir='ls --color=auto --format=long'

# Directory navigation
alias ..='cd ..'
alias ...='cd ../..'
alias ....='cd ../../..'
alias ~='cd ~'
alias -- -='cd -'

# Enhanced grep with color
alias grep='grep --color=auto'
alias fgrep='fgrep --color=auto'
alias egrep='egrep --color=auto'
alias rg='rg --color=auto'

# File operations
alias cp='cp -iv'
alias mv='mv -iv'
alias rm='rm -iv'
alias mkdir='mkdir -pv'
alias rmdir='rmdir -v'

# Shortcuts for common tasks
alias h='history'
alias j='jobs -l'
alias which='type -a'
alias path='echo -e ${PATH//:/\\n}'
alias now='date +"%Y-%m-%d %H:%M:%S"'
alias timestamp='date +%s'

# Python/development aliases
alias py='python'
alias ipy='python -m IPython'
alias pip='python -m pip'
alias pytest='python -m pytest'
alias ptest='python -m pytest -v --tb=short'
alias pcover='python -m pytest --cov=authly --cov-report=term-missing'

# Python debugging & profiling
alias pyspy='py-spy top --pid'  # Real-time Python profiling
alias pyflame='python -m flamegraph'  # Flame graphs
alias pdb='python -m pdb'  # Python debugger
alias profile='python -m cProfile -s cumulative'
alias memprofile='python -m memory_profiler'
alias pystack='python -c "import traceback; traceback.print_stack()"'

# Authly-specific aliases
alias authly-status='python -m authly admin status'
alias authly-login='python -m authly admin auth login'
alias authly-clients='python -m authly admin client list'
alias authly-scopes='python -m authly admin scope list'
alias authly-logs='tail -f /var/log/authly/*.log 2>/dev/null || echo "No logs available"'

# Database access - direct connection to authly database
alias psql='/opt/postgresql/bin/psql -h /run/postgresql -U authly -d authly'
alias pg='psql'

# Cache access - direct connection to KeyDB/Redis
alias redis='keydb-cli -h localhost -p 6379'
alias keydb='keydb-cli -h localhost -p 6379'
alias redis-cli='keydb-cli -h localhost -p 6379'

# Docker/container helpers
alias dps='docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"'
alias dlogs='docker logs -f'
alias dexec='docker exec -it'
alias dstats='docker stats --no-stream'
alias dimages='docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"'
alias dclean='docker system prune -f'

# System monitoring - standard sysadmin aliases
# Note: 'w' command is already available and shows uptime/load
alias meminfo='free -h'
alias cpuinfo='lscpu | grep -E "^(Model name|CPU\(s\)|Thread|Core|Socket)"'
alias diskinfo='df -h'
alias du='du -h'
alias df='df -h'
alias mount='mount | column -t'
alias ports='netstat -tuln 2>/dev/null || ss -tuln'
alias psg='ps aux | grep -v grep | grep'
alias top='htop || top'
alias iotop='iotop -o'  # Only show processes doing I/O

# Process management
alias ps='ps auxf'
alias pstree='pstree -p'
alias kill='kill -9'
alias killall='killall -9'

# Network debugging
alias netstat='netstat -antp 2>/dev/null'
alias ss='ss -antp'
alias lsof='lsof -i'
alias nmap='nmap -sT'  # TCP connect scan
alias tcpdump='tcpdump -i any -nn'
alias ping='ping -c 5'
alias traceroute='traceroute -n'
alias mtr='mtr --report-cycles 10'
alias dig='dig +short'
alias nslookup='nslookup'
alias wget='wget -c'  # Continue partial downloads
alias curl='curl -L'  # Follow redirects
alias ifconfig='ip addr'
alias route='ip route'
alias arp='ip neigh'

# Security & auditing
alias last='last -a'  # Show last logins
alias lastlog='lastlog'
alias fail2ban='grep "Ban" /var/log/fail2ban.log 2>/dev/null'
alias connections='ss -tan state established'
alias listening='ss -tln'
alias openfiles='lsof | wc -l'
alias syslog='tail -f /var/log/messages 2>/dev/null || journalctl -f'

# Performance profiling
alias iostat='iostat -x 1'  # Extended I/O stats
alias vmstat='vmstat 1'  # Virtual memory stats
alias mpstat='mpstat -P ALL 1'  # CPU stats per core
alias sar='sar -u 1 10'  # System activity
alias dstat='dstat -cdnmgyl'  # Comprehensive stats

# Service management
alias services='rc-status -a 2>/dev/null || systemctl status'
alias restart='rc-service $1 restart 2>/dev/null || systemctl restart $1'

# Log viewing
alias logs='tail -f /var/log/*.log'
alias errors='grep -i error /var/log/*.log'
alias warnings='grep -i warning /var/log/*.log'
alias messages='tail -f /var/log/messages 2>/dev/null'

# Debugging shortcuts
alias strace='strace -f -e trace=network,file'
alias ltrace='ltrace -f'
alias gdb='gdb -q'  # Quiet mode

# Improved directory listing with tree-like structure (if tree is available)
if command -v tree &> /dev/null; then
    alias lt='tree -L 1 --dirsfirst'
    alias ltt='tree -L 2 --dirsfirst'
    alias lttt='tree -L 3 --dirsfirst'
fi

# Set a colored prompt (without directory to keep it clean)
export PS1='\[\033[01;32m\]authly\[\033[00m\]> '

# Enable bash completion for color in git diff and other commands
export GIT_PAGER='less -R'
export LESS='-R'
export LESSOPEN='| /usr/bin/env lesspipe %s 2>&-'

# Setup PostgreSQL client configuration
if [ -f /tmp/setup-scripts/psqlrc ]; then
    cp /tmp/setup-scripts/psqlrc /home/authly/.psqlrc
    chown authly:authly /home/authly/.psqlrc
fi

# Setup Redis/KeyDB client configuration
if [ -f /tmp/setup-scripts/redisclirc ]; then
    cp /tmp/setup-scripts/redisclirc /home/authly/.redisclirc
    chown authly:authly /home/authly/.redisclirc
fi

# Advanced troubleshooting functions

# Show top memory consumers
topmem() {
    ps aux | sort -nrk 4 | head -10
}

# Show top CPU consumers
topcpu() {
    ps aux | sort -nrk 3 | head -10
}

# Find process by port
whoisport() {
    lsof -i :"$1" 2>/dev/null || ss -lptn "sport = :$1"
}

# Check SSL certificate
checkcert() {
    echo | openssl s_client -connect "$1":443 2>/dev/null | openssl x509 -noout -dates
}

# Monitor HTTP endpoint
monitor_endpoint() {
    while true; do
        curl -s -o /dev/null -w "%{http_code} %{time_total}s\n" "$1"
        sleep 1
    done
}

# Analyze Authly logs
authly_errors() {
    grep -E "ERROR|CRITICAL" /var/log/authly/*.log 2>/dev/null || echo "No errors found"
}

# Show connection count by IP
connection_count() {
    ss -tan state established | awk '{print $4}' | cut -d':' -f1 | sort | uniq -c | sort -rn | head -10
}

# Python process inspection
pyinfo() {
    local pid=${1:-$(pgrep -f "python.*authly" | head -1)}
    if [ -n "$pid" ]; then
        echo "Python process $pid:"
        echo "Memory: $(ps -o rss= -p $pid | awk '{print $1/1024"MB"}')"
        echo "CPU: $(ps -o %cpu= -p $pid)%"
        echo "Threads: $(ls /proc/$pid/task 2>/dev/null | wc -l)"
        echo "Open files: $(lsof -p $pid 2>/dev/null | wc -l)"
    else
        echo "No Python/Authly process found"
    fi
}

# Database connection check
dbcheck() {
    psql -c "SELECT version();" >/dev/null 2>&1 && echo "✓ PostgreSQL connected" || echo "✗ PostgreSQL connection failed"
    redis ping >/dev/null 2>&1 && echo "✓ Redis connected" || echo "✗ Redis connection failed"
}

# Show system resource summary
sysinfo() {
    echo "=== System Resources ==="
    echo "CPU: $(grep -c processor /proc/cpuinfo) cores"
    free -h | grep Mem
    df -h / | tail -1
    echo "Load: $(uptime | awk -F'load average:' '{print $2}')"
    echo "Processes: $(ps aux | wc -l)"
    echo "Connections: $(ss -tan | wc -l)"
}

cd /app

# Get Authly version
AUTHLY_VERSION=$(python -c "from authly._version import __version__; print(__version__)" 2>/dev/null || echo "unknown")

echo "================================================================================"
echo "Welcome to Authly Standalone v${AUTHLY_VERSION}"
echo "================================================================================"
echo "⚠️  WARNING: This container uses insecure default secrets for development/testing only!"
echo "   For production, always provide your own secure JWT_SECRET_KEY and JWT_REFRESH_SECRET_KEY"
echo ""
echo "Services: PostgreSQL 17, KeyDB (Redis-compatible), and Authly are running"
echo ""
echo "Available commands:"
echo "  • authly --help                   # Main CLI with all commands"
echo "  • man authly                      # Manual with how-to guides"
echo "  • psql                            # Direct database access with tab completion"
echo "  • redis                           # Direct cache access (KeyDB/Redis)"
echo "  • simple-auth-flow --help         # Full test: simple-auth-flow"
echo "  • run-end-to-end-test --help      # Full test: run-end-to-end-test comprehensive"
echo "  • unlock-admin-account            # Unlock admin account if locked out"
echo ""

# Setup FAST bash completion for authly (avoids slow Python startup)
cat > /tmp/authly-completion.bash << 'COMPLETION_EOF'
# Fast Authly CLI completion using static command structure
# This provides instant (<50ms) tab completion for common commands

_authly_fast_completion() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local prev="${COMP_WORDS[COMP_CWORD-1]}"
    COMPREPLY=()
    
    # Build the command path to understand context
    local cmd_path=""
    local i
    local start_idx=0
    
    # Find where authly command starts (handle "python -m authly" case)
    for ((i=0; i<=COMP_CWORD; i++)); do
        if [[ "${COMP_WORDS[i]}" == "authly" ]]; then
            start_idx=$i
            break
        fi
    done
    
    # Build command path from authly onwards, skipping options
    for ((i=start_idx; i<COMP_CWORD; i++)); do
        if [[ "${COMP_WORDS[i]}" != -* ]]; then
            if [[ -z "$cmd_path" ]]; then
                cmd_path="${COMP_WORDS[i]}"
            else
                cmd_path="${cmd_path} ${COMP_WORDS[i]}"
            fi
        fi
    done
    
    # Determine what to complete based on command path
    local opts=""
    
    # Match command paths and provide appropriate completions
    case "$cmd_path" in
        "authly")
            if [[ "$cur" == --* ]]; then
                opts="--version --commands --install-completion --help"
            else
                opts="admin serve"
            fi
            ;;
        "authly admin")
            if [[ "$cur" == --* ]]; then
                opts="--config --verbose --dry-run --help"
            else
                opts="auth client scope status"
            fi
            ;;
        "authly serve")
            opts="--host --port --workers --embedded --seed --log-level --access-log --no-access-log --help"
            ;;
        "authly admin auth")
            opts="login logout whoami status info refresh"
            ;;
        "authly admin client")
            opts="create list show update delete regenerate-secret"
            ;;
        "authly admin scope")
            opts="create list show update delete defaults"
            ;;
        # Auth subcommands with options
        "authly admin auth login")
            opts="--username --password --scope --api-url --show-token --help"
            ;;
        "authly admin auth logout")
            opts="--help"
            ;;
        "authly admin auth whoami")
            opts="--verbose --help"
            ;;
        "authly admin auth status"|"authly admin status")
            opts="--verbose --help"
            ;;
        "authly admin auth info")
            opts="--help"
            ;;
        "authly admin auth refresh")
            opts="--help"
            ;;
        # Client subcommands with options
        "authly admin client create")
            opts="--name --type --redirect-uri --scope --client-uri --logo-uri --tos-uri --policy-uri --auth-method --no-pkce --help"
            ;;
        "authly admin client list")
            opts="--show-inactive --output --help"
            ;;
        "authly admin client show")
            opts="--help"
            ;;
        "authly admin client update")
            opts="--name --redirect-uri --scope --client-uri --logo-uri --tos-uri --policy-uri --deactivate --reactivate --help"
            ;;
        "authly admin client delete")
            opts="--confirm --help"
            ;;
        "authly admin client regenerate-secret")
            opts="--confirm --help"
            ;;
        # Scope subcommands with options
        "authly admin scope create")
            opts="--name --description --default --help"
            ;;
        "authly admin scope list"|"authly admin scope defaults")
            opts="--help"
            ;;
        "authly admin scope show")
            opts="--help"
            ;;
        "authly admin scope update")
            opts="--description --make-default --remove-default --help"
            ;;
        "authly admin scope delete")
            opts="--confirm --help"
            ;;
        *)
            # Unknown path, no completions
            return 0
            ;;
    esac
    
    COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
}

# Register the fast completions
complete -F _authly_fast_completion python
complete -F _authly_fast_completion authly
COMPLETION_EOF

# Source the completion
if [ -f /tmp/authly-completion.bash ]; then
    source /tmp/authly-completion.bash
fi
EOF

# Create a basic .vimrc for better editing experience
cat > /home/authly/.vimrc << 'EOF'
" Basic vim configuration for Authly container
syntax on
set number
set relativenumber
set autoindent
set expandtab
set tabstop=4
set shiftwidth=4
set softtabstop=4
set cursorline
set showcmd
set wildmenu
set incsearch
set hlsearch
set ignorecase
set smartcase
set background=dark
set mouse=a
set encoding=utf-8
set fileencoding=utf-8
set ruler
set laststatus=2

" Python-specific settings
autocmd FileType python setlocal expandtab shiftwidth=4 softtabstop=4

" YAML-specific settings  
autocmd FileType yaml setlocal expandtab shiftwidth=2 softtabstop=2

" JSON-specific settings
autocmd FileType json setlocal expandtab shiftwidth=2 softtabstop=2

" Markdown-specific settings
autocmd FileType markdown setlocal wrap linebreak

" Enable file type detection
filetype plugin indent on

" Color scheme improvements for dark terminals
if &t_Co > 2 || has("gui_running")
    syntax on
    set t_Co=256
endif

" Highlight trailing whitespace
highlight ExtraWhitespace ctermbg=red guibg=red
match ExtraWhitespace /\s\+$/
EOF

# Create .inputrc for better readline experience
cat > /home/authly/.inputrc << 'EOF'
# Readline configuration for better CLI experience
set colored-stats On
set completion-ignore-case On
set completion-prefix-display-length 3
set mark-symlinked-directories On
set show-all-if-ambiguous On
set show-all-if-unmodified On
set visible-stats On

# History search with arrow keys
"\e[A": history-search-backward
"\e[B": history-search-forward

# Ctrl+Left/Right to move by word
"\e[1;5C": forward-word
"\e[1;5D": backward-word

# Enable vi mode (comment out if you prefer emacs mode)
# set editing-mode vi
EOF

# Create .screenrc for better screen/tmux experience
cat > /home/authly/.screenrc << 'EOF'
# Screen configuration
startup_message off
defscrollback 10000
hardstatus alwayslastline
hardstatus string '%{= kG}[ %{G}%H %{g}][%= %{= kw}%?%-Lw%?%{r}(%{W}%n*%f%t%?(%u)%?%{r})%{w}%?%+Lw%?%?%= %{g}][%{B} %Y-%m-%d %{W}%c %{g}]'

# Enable 256 colors
term screen-256color

# Enable mouse scrolling
termcapinfo xterm* ti@:te@
EOF

# Create .nanorc for nano users
cat > /home/authly/.nanorc << 'EOF'
# Nano configuration for better editing
set autoindent
set linenumbers
set mouse
set smooth
set tabsize 4
set tabstospaces
set constantshow
set titlecolor brightwhite,blue
set statuscolor brightwhite,green
set keycolor cyan
set functioncolor green
set numbercolor yellow
set softwrap

# Syntax highlighting
include "/usr/share/nano/*.nanorc"
EOF

# Create a custom MOTD-like greeting function
cat >> /home/authly/.bashrc << 'EOF'

# Show system info on login (only for interactive shells)
if [[ $- == *i* ]]; then
    # Function to display system info
    show_system_info() {
        echo -e "\033[1;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
        echo -e "  \033[1;32mSystem:\033[0m $(uname -n) | \033[1;32mKernel:\033[0m $(uname -r | cut -d'-' -f1)"
        # BusyBox-compatible uptime parsing - extract just the uptime duration
        local uptime_str=$(uptime | sed 's/.*up *//' | awk -F',' '{print $1}')
        echo -e "  \033[1;32mMemory:\033[0m $(free -h | awk '/^Mem:/ {print $3 "/" $2}') | \033[1;32mUptime:\033[0m $uptime_str"
        echo -e "  \033[1;32mProcesses:\033[0m $(ps aux | wc -l) | \033[1;32mLoad:\033[0m$(uptime | awk -F'load average:' '{print $2}')"
        echo -e "\033[1;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    }
    
    # Only show on first login, not on every new shell
    if [ -z "$AUTHLY_INFO_SHOWN" ]; then
        export AUTHLY_INFO_SHOWN=1
        show_system_info
    fi
fi

# Useful functions
mkcd() { mkdir -p "$1" && cd "$1"; }
extract() {
    if [ -f "$1" ]; then
        case "$1" in
            *.tar.bz2) tar xjf "$1" ;;
            *.tar.gz) tar xzf "$1" ;;
            *.bz2) bunzip2 "$1" ;;
            *.gz) gunzip "$1" ;;
            *.tar) tar xf "$1" ;;
            *.zip) unzip "$1" ;;
            *.Z) uncompress "$1" ;;
            *) echo "'$1' cannot be extracted" ;;
        esac
    else
        echo "'$1' is not a valid file"
    fi
}

# Quick JSON prettifier
json() {
    if [ -t 0 ]; then
        python -m json.tool "$@" | pygmentize -l json 2>/dev/null || python -m json.tool "$@"
    else
        python -m json.tool | pygmentize -l json 2>/dev/null || python -m json.tool
    fi
}

# Quick YAML validator
yaml() {
    python -c "import yaml, sys; yaml.safe_load(sys.stdin)" < "$1" && echo "✓ Valid YAML"
}
EOF

# Set proper ownership for all config files
chown authly:authly /home/authly/.vimrc /home/authly/.inputrc /home/authly/.screenrc /home/authly/.nanorc 2>/dev/null || true

# Setup man page directory if needed
mkdir -p /usr/share/man/man1

# Create symlink for man page access
if [ -f /usr/share/man/man1/authly.1 ]; then
    # Ensure man database is updated
    mandb 2>/dev/null || true
    echo "✅ Man page installed. Try: man authly"
fi

echo "✅ Shell environment configured with aliases, colors, and editor settings"