#!/bin/bash

# Born2beroot System Monitoring Script
# Created by Sude Naz Karayıldırım

# Create the monitoring message
{
    echo "╔══════════════════════════════════════╗"
    echo "║        SYSTEM MONITORING INFO        ║"
    echo "╚══════════════════════════════════════╝"

    # 1. Architecture and Kernel version
    arch=$(uname -a)
    echo "#Architecture: $arch"

    # 2. Physical CPU count
    pcpu=$(grep "physical id" /proc/cpuinfo 2>/dev/null | sort -u | wc -l)
    if [ "$pcpu" -eq 0 ]; then
        pcpu=$(nproc)
    fi
    echo "#CPU physical: $pcpu"

    # 3. Virtual CPU count  
    vcpu=$(nproc)
    echo "#vCPU: $vcpu"

    # 4. RAM usage
    memory_usage=$(free -m | awk 'NR==2{printf "%s/%sMB (%.2f%%)", $3,$2,$3*100/$2}')
    echo "#Memory Usage: $memory_usage"

    # 5. Disk usage - Fixed
    disk_usage=$(df -h --total 2>/dev/null | grep '^total' | awk '{printf "%s/%s (%s)", $3, $2, $5}')
    if [ -z "$disk_usage" ]; then
        disk_usage=$(df -h / | awk 'NR==2{printf "%s/%s (%s)", $3, $2, $5}')
    fi
    echo "#Disk Usage: $disk_usage"

    # 6. CPU load percentage - Fixed
    cpu_load=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{printf "%.1f%%", 100 - $1}')
    if [ -z "$cpu_load" ]; then
        cpu_load=$(vmstat 1 2 2>/dev/null | tail -1 | awk '{if(NF>=15) printf "%.1f%%", 100-$15; else print "N/A"}')
    fi
    echo "#CPU load: $cpu_load"

    # 7. Last reboot date
    last_boot=$(who -b 2>/dev/null | awk '{print $3, $4}')
    if [ -z "$last_boot" ]; then
        last_boot=$(uptime -s 2>/dev/null || date)
    fi
    echo "#Last boot: $last_boot"

    # 8. LVM usage
    if command -v lsblk >/dev/null 2>&1; then
        if [ $(lsblk | grep -i "lvm" | wc -l) -eq 0 ]; then
            lvm_use="no"
        else
            lvm_use="yes"
        fi
    else
        if [ -d "/dev/mapper" ] && [ $(ls /dev/mapper/ | grep -v control | wc -l) -gt 0 ]; then
            lvm_use="yes"
        else
            lvm_use="no"
        fi
    fi
    echo "#LVM use: $lvm_use"

    # 9. TCP connections
    if command -v ss >/dev/null 2>&1; then
        tcp_conn=$(ss -ta 2>/dev/null | grep -i estab | wc -l)
    else
        tcp_conn=$(netstat -tan 2>/dev/null | grep ESTABLISHED | wc -l)
    fi
    echo "#Connections TCP: $tcp_conn ESTABLISHED"

    # 10. Active user count
    user_log=$(who | wc -l)
    echo "#User log: $user_log"

    # 11. Network information
    ip_addr=$(hostname -I 2>/dev/null | awk '{print $1}')
    if [ -z "$ip_addr" ]; then
        ip_addr=$(ip route get 8.8.8.8 2>/dev/null | awk 'NR==1 {print $7}')
    fi

    if command -v ip >/dev/null 2>&1; then
        mac_addr=$(ip link show 2>/dev/null | grep "link/ether" | awk '{print $2}' | head -n1)
    else
        mac_addr=$(ifconfig 2>/dev/null | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}' | head -n1)
    fi

    echo "#Network: IP $ip_addr ($mac_addr)"

    # 12. Sudo command count - Fixed
    sudo_cmd=0
    if [ -f "/var/log/sudo/sudo.log" ]; then
        sudo_cmd=$(grep -c "COMMAND" /var/log/sudo/sudo.log 2>/dev/null || echo "0")
    elif [ -f "/var/log/auth.log" ]; then
        sudo_cmd=$(grep -c "sudo.*COMMAND" /var/log/auth.log 2>/dev/null || echo "0")
    elif [ -f "/var/log/secure" ]; then
        sudo_cmd=$(grep -c "sudo.*COMMAND" /var/log/secure 2>/dev/null || echo "0")
    fi
    echo "#Sudo: $sudo_cmd cmd"

    # Bottom line (optional)
    echo "════════════════════════════════════════"
} | wall