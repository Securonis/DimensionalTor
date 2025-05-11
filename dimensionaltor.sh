#!/usr/bin/env bash

# program information
readonly prog_name="dimensionaltor"
readonly version="1.0.0"
readonly signature="Copyright (C) 2025 root0emir"
readonly git_url="https://github.com/Securonis/dimensionaltor"


export red="$(tput setaf 1)"
export green="$(tput setaf 2)"
export blue="$(tput setaf 4)"
export white="$(tput setaf 7)"
export b="$(tput bold)"
export reset="$(tput sgr0)"

## Directories
# Create directories if they don't exist
readonly data_dir="$HOME/.dimensionaltor/data"      # config files
readonly backup_dir="$HOME/.dimensionaltor/backups"   # backups

## Network settings
#
# the UID that Tor runs as (varies from system to system)
# $(id -u debian-tor) #Debian/Ubuntu
readonly tor_uid="$(id -u debian-tor)"

# Tor TransPort
readonly trans_port="9040"

# Tor DNSPort
readonly dns_port="5353"

# Tor VirtualAddrNetworkIPv4
readonly virtual_address="10.192.0.0/10"

# LAN destinations that shouldn't be routed through Tor
readonly non_tor="127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"


## Show program banner
banner() {
printf "${b}${white}
  _____  _                          _                   _ _______         
 |  __ \(_)                        (_)                 | |__   __|        
 | |  | |_ _ __ ___   ___ _ __  ___ _  ___  _ __   __ _| |  | | ___  _ __ 
 | |  | | | '_ ` _ \ / _ \ '_ \/ __| |/ _ \| '_ \ / _` | |  | |/ _ \| '__|
 | |__| | | | | | | |  __/ | | \__ \ | (_) | | | | (_| | |  | | (_) | |   
 |_____/|_|_| |_| |_|\___|_| |_|___/_|\___/|_| |_|\__,_|_|  |_|\___/|_|   
                                                                                                                                                   
  v${version}                                              

${reset}\\n\\n"
}


## Print a message and exit with (1) when an error occurs
die() {
    printf "${red}%s${reset}\\n" "[ERROR] $*" >&2
    exit 1
}


## Print information
info() {
    printf "${b}${blue}%s${reset} ${b}%s${reset}\\n" "::" "${@}"

}


## Print `OK` messages
msg() {
    printf "${b}${green}%s${reset} %s\\n\\n" "[OK]" "${@}"
}


## Check if the program run as a root
check_root() {
    if [[ "${UID}" -ne 0 ]]; then
        die "DimensionalTor: Please run this program as root!"
    fi
}


## Display program version and License
print_version() {
    printf "%s\\n" "${prog_name} ${version}"
    printf "%s\\n" "${signature}"
    printf "%s\\n" "License MIT <https://opensource.org/licenses/MIT>"
    printf "%s\\n" "This is free software: you are free to change and redistribute it."
    printf "%s\\n" "There is NO WARRANTY, to the extent permitted by law."
    exit 0
}


## Configure general settings
#
# - packages: tor, curl
# - program directories: ${data_dir}, ${backup_dir}
# - tor configuration file: /etc/tor/torrc
# - DNS settings: /etc/resolv.conf
setup_general() {
    info "Checking settings"

    # packages
    declare -a dependencies=('tor' 'curl')
    for package in "${dependencies[@]}"; do
        if ! hash "${package}" 2>/dev/null; then
            die "'${package}' is not installed, exiting!"
        fi
    done

    # Create directories if they don't exist
    mkdir -p "${backup_dir}" "${data_dir}"

    # torrc check
    if [[ ! -f /etc/tor/torrc ]]; then
        die "/etc/tor/torrc file not found, check Tor configuration!"
    fi

    printf "%s\\n" "Setting up /etc/tor/torrc"

    # Backup torrc if it exists
    cp -f /etc/tor/torrc "${backup_dir}/torrc.backup" || die "Cannot backup '/etc/tor/torrc'!"

    # Create a new torrc file with the required settings
    cat > "${data_dir}/torrc" << EOF
# Created by DimensionalTor
User debian-tor
VirtualAddrNetworkIPv4 ${virtual_address}
AutomapHostsSuffixes .onion,.exit
AutomapHostsOnResolve 1
TransPort ${trans_port}
DNSPort ${dns_port}
EOF

    cp -f "${data_dir}/torrc" /etc/tor/torrc || die "Cannot copy new '/etc/tor/torrc'!"

    # DNS settings: /etc/resolv.conf
    printf "%s\\n" "Configuring resolv.conf file to use Tor DNSPort"

    # backup current resolv.conf
    cp /etc/resolv.conf "${backup_dir}/resolv.conf.backup" || die "Cannot backup '/etc/resolv.conf'!"

    # write new nameserver
    printf "%s\\n" "nameserver 127.0.0.1" > /etc/resolv.conf

    # reload systemd daemons
    printf "%s\\n" "Reloading systemd services"
    systemctl --system daemon-reload
}


## iptables settings
#
# This function is used with args in start() and stop() functions
# for set/restore iptables.
#
# Usage: setup_iptables <arg>
#
# function args:
#       tor_proxy -> set rules for Tor transparent proxy
#       default   -> restore default rules
setup_iptables() {
    case "$1" in
        tor_proxy)
            printf "%s\\n" "Setting up iptables rules"

            ## Flush current iptables rules
            iptables -F
            iptables -X
            iptables -t nat -F
            iptables -t nat -X
            iptables -P INPUT ACCEPT
            iptables -P FORWARD ACCEPT
            iptables -P OUTPUT ACCEPT

            ## *nat OUTPUT (For local redirection)
            #
            # nat .onion addresses
            iptables -t nat -A OUTPUT -d $virtual_address -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j REDIRECT --to-ports $trans_port

            # nat dns requests to Tor
            iptables -t nat -A OUTPUT -d 127.0.0.1/32 -p udp -m udp --dport 53 -j REDIRECT --to-ports $dns_port

            # Don't nat the Tor process, the loopback, or the local network
            iptables -t nat -A OUTPUT -m owner --uid-owner $tor_uid -j RETURN
            iptables -t nat -A OUTPUT -o lo -j RETURN

            # Allow lan access for hosts in $non_tor
            for lan in $non_tor; do
                iptables -t nat -A OUTPUT -d $lan -j RETURN
            done

            # Redirects all other pre-routing and output to Tor's TransPort
            iptables -t nat -A OUTPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j REDIRECT --to-ports $trans_port

            ## *filter INPUT
            iptables -A INPUT -m state --state ESTABLISHED -j ACCEPT
            iptables -A INPUT -i lo -j ACCEPT

            # Drop everything else
            iptables -A INPUT -j DROP

            ## *filter FORWARD
            iptables -A FORWARD -j DROP

            ## *filter OUTPUT
            #
            # Fix for potential kernel transproxy packet leaks
            # see: https://lists.torproject.org/pipermail/tor-talk/2014-March/032507.html
            iptables -A OUTPUT -m conntrack --ctstate INVALID -j DROP

            iptables -A OUTPUT -m state --state INVALID -j DROP
            iptables -A OUTPUT -m state --state ESTABLISHED -j ACCEPT

            # Allow Tor process output
            iptables -A OUTPUT -m owner --uid-owner $tor_uid -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m state --state NEW -j ACCEPT

            # Allow loopback output
            iptables -A OUTPUT -d 127.0.0.1/32 -o lo -j ACCEPT

            # Tor transproxy magic
            iptables -A OUTPUT -d 127.0.0.1/32 -p tcp -m tcp --dport $trans_port --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT

            # Drop everything else
            iptables -A OUTPUT -j DROP

            ## Set default policies to DROP
            iptables -P INPUT DROP
            iptables -P FORWARD DROP
            iptables -P OUTPUT DROP
        ;;

        default)
            printf "%s\\n" "Restoring default iptables rules"

            # Flush iptables rules
            iptables -F
            iptables -X
            iptables -t nat -F
            iptables -t nat -X
            iptables -P INPUT ACCEPT
            iptables -P FORWARD ACCEPT
            iptables -P OUTPUT ACCEPT
        ;;
    esac
}


## Check public IP address using check.torproject.org
check_ip() {
    info "Checking public IP address"

    local url="https://check.torproject.org"
    local hostport="localhost:9050"
    
    local result=$(curl --socks5 "${hostport}" --socks5-hostname "${hostport}" -s "${url}" | grep -oE '<strong>[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+</strong>' | sed -e 's/<[^>]*>//g')
    
    if [[ -n "$result" ]]; then
        printf "${green}%s${reset} %s\\n" "Current Tor IP Address:" "$result"
    else
        printf "${red}%s${reset}\\n" "Failed to get IP address. Check your Tor connection."
    fi
}


## Check status of program and services
#
# - tor.service
# - tor settings (check if Tor works correctly)
# - public IP Address
check_status() {
    info "Checking current status of Tor service"

    if systemctl is-active tor.service >/dev/null 2>&1; then
        msg "Tor service is active"
    else
        die "Tor service is not running! Exiting!"
    fi

    # make an HTTP request with curl at: https://check.torproject.org/
    # and grep the necessary strings from the HTML page to test connection
    # with Tor
    info "Checking Tor network settings"

    # curl SOCKS options:
    #   --socks5 <host[:port]> SOCKS5 proxy on given host + port
    #   --socks5-hostname <host[:port]> SOCKS5 proxy, pass host name to proxy
    local hostport="localhost:9050"
    local url="https://check.torproject.org/"

    if curl --socks5 "${hostport}" --socks5-hostname "${hostport}" -s "${url}" | cat | grep -q "Congratulations"; then
        msg "Your system is configured to use Tor"
    else
        printf "${red}%s${reset}\\n\\n" "Your system is not using Tor!"
        printf "%s\\n" "Try another Tor circuit with '${prog_name} restart'"
        exit 1
    fi

    check_ip
}


## Start transparent proxy through Tor
start() {
    check_root

    # Exit if tor.service is already active
    if systemctl is-active tor.service >/dev/null 2>&1; then
        die "Tor service is already active, stop it first"
    fi

    banner
    sleep 2
    setup_general

    printf "\\n"
    info "Starting Transparent Proxy"

    # disable IPv6
    printf "%s\\n" "Disabling IPv6"
    sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1
    sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1

    # start tor.service
    printf "%s\\n" "Starting Tor service"

    if ! systemctl start tor.service >/dev/null 2>&1; then
        die "Cannot start tor service, exiting!"
    fi

    # set new iptables rules
    setup_iptables tor_proxy

    # check program status
    printf "\\n"
    check_status

    printf "\\n${b}${green}%s${reset} %s\\n" \
            "[OK]" "Transparent Proxy activated, your system is now under Tor"
}


## Stop transparent proxy
#
# stop connection with Tor Network and return to clearnet navigation
stop() {
    check_root

    # don't run function if tor.service is NOT running!
    if systemctl is-active tor.service >/dev/null 2>&1; then
        info "Stopping Transparent Proxy"

        # resets default iptables rules
        setup_iptables default

        printf "%s\\n" "Stopping Tor service"
        systemctl stop tor.service

        # restore /etc/resolv.conf:
        #
        # restore file with resolvconf if exists otherwise copy the original
        # file from backup directory.
        printf "%s\\n" "Restoring default DNS"

        if hash resolvconf 2>/dev/null; then
            resolvconf -u
        else
            cp "${backup_dir}/resolv.conf.backup" /etc/resolv.conf
        fi

        # enable IPv6
        printf "%s\\n" "Enabling IPv6"
        sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1
        sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null 2>&1

        # restore default /etc/tor/torrc
        printf "%s\\n" "Restoring default /etc/tor/torrc"
        cp "${backup_dir}/torrc.backup" /etc/tor/torrc

        printf "\\n${b}${green}%s${reset} %s\\n" "[-]" "Transparent Proxy stopped"
        exit 0
    else
        die "Tor service is not running! Exiting!"
    fi
}


## Restart
#
# restart tor.service (i.e. get new Tor exit node)
# and change public IP Address
restart() {
    check_root

    if systemctl is-active tor.service >/dev/null 2>&1; then
        info "Changing IP address"

        systemctl restart tor.service
        sleep 1
        check_ip
        exit 0
    else
        die "Tor service is not running! Exiting!"
    fi
}


## Show interactive menu
show_menu() {
    check_root
    clear
    banner
    
    while true; do
        printf "${b}${white}%s${reset}\\n\\n" "============= DIMENSIONALTOR MENU ============="
        printf "${b}${white}%s${reset}\\n" "1. Start Tor Transparent Proxy"
        printf "${b}${white}%s${reset}\\n" "2. Stop Tor Transparent Proxy"
        printf "${b}${white}%s${reset}\\n" "3. Restart Tor (Change IP)"
        printf "${b}${white}%s${reset}\\n" "4. Check Status"
        printf "${b}${white}%s${reset}\\n" "5. Show IP Information"
        printf "${b}${white}%s${reset}\\n" "6. Show Version"
        printf "${b}${white}%s${reset}\\n" "0. Exit"
        printf "${b}${white}%s${reset}\\n\\n" "=============================================="
        
        read -p "Enter your choice [0-6]: " choice
        printf "\\n"
        
        case $choice in
            1) 
               clear
               start
               printf "\\nPress Enter to continue..."
               read
               ;;
            2) 
               clear
               stop
               printf "\\nPress Enter to continue..."
               read
               ;;
            3) 
               clear
               restart
               printf "\\nPress Enter to continue..."
               read
               ;;
            4) 
               clear
               check_status
               printf "\\nPress Enter to continue..."
               read
               ;;
            5) 
               clear
               check_ip
               printf "\\nPress Enter to continue..."
               read
               ;;
            6) 
               clear
               print_version
               printf "\\nPress Enter to continue..."
               read
               ;;
            0) exit 0 ;;
            *) 
               printf "${red}%s${reset}\\n" "Invalid option, try again."
               sleep 2
               ;;
        esac
        
        # Clear screen for next menu iteration
        clear
        banner
    done
}

# Call main function directly with menu
show_menu
