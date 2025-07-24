# 🖥️ Born2beRoot - Sistem Yönetimi Projesi

<div align="center">

![42 School](https://img.shields.io/badge/School-42-black?style=for-the-badge&logo=42)
![System Admin](https://img.shields.io/badge/System-Administration-blue?style=for-the-badge&logo=linux)
![Score](https://img.shields.io/badge/Score-125%2F100-gold?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Completed-success?style=for-the-badge)

**Sanal makine ortamında güvenli Debian server kurulumu ve sistem yönetimi projesi**

</div>

---

## 📝 Proje Açıklaması

Born2beRoot, **sistem yönetimi**, **ağ güvenliği** ve **server hardening** temellerini öğretmeyi amaçlayan bir 42 School projesidir. Bu projede, hiçbir grafik arayüz kullanmadan minimum servis ile güvenli bir Linux server kurulumu gerçekleştirilir.

## 🎯 Öğrenilen Konular

- **Virtual Machine** yönetimi ve konfigürasyonu
- **Linux sistem yönetimi** (user management, permissions)
- **Network güvenliği** (SSH hardening, firewall configuration)
- **Security policies** (password policies, sudo configuration)
- **System monitoring** ve automation (cron jobs, shell scripting)
- **Disk management** (LVM, encrypted partitions)

## ⚙️ Teknik Özellikler

### 🔧 **Sistem Konfigürasyonu**
- **OS**: Debian (Latest Stable)
- **Virtualization**: VirtualBox
- **Encryption**: LVM with encrypted partitions
- **Services**: SSH, UFW, AppArmor, Cron

### 🛡️ **Güvenlik Implementasyonları**
- **SSH**: Port 4242, Root login disabled
- **Firewall**: UFW configured, only essential ports open
- **Password Policy**: Strong requirements (10+ chars, complexity rules)
- **Sudo Configuration**: Secure settings, command logging
- **User Management**: Proper group assignments and permissions

### 📊 **Monitoring System**
- **Script**: Custom system monitoring script
- **Data Collection**: CPU, Memory, Disk, Network statistics
- **Automation**: Cron job every 10 minutes
- **Display**: Wall broadcast to all terminals

## 📋 Proje Gereksinimleri

### ✅ **Mandatory Requirements**
- [x] Debian kurulumu (GUI yasaklanmış)
- [x] En az 2 encrypted partition (LVM)
- [x] SSH servis (port 4242)
- [x] UFW firewall yapılandırması
- [x] Güçlü password policy
- [x] Sudo güvenli konfigürasyonu
- [x] Monitoring script + cron job
- [x] User ve group yönetimi

### 🎁 **Bonus Features**
- [x] WordPress stack (Lighttpd, MariaDB, PHP)
- [x] Ek faydalı servis kurulumu
- [x] Gelişmiş partition yapısı

## 🔍 Monitoring Script Çıktısı

```bash
#Architecture: Linux debian 4.19.0-16-amd64
#CPU physical : 1
#vCPU : 2
#Memory Usage: 157/987MB (15.90%)
#Disk Usage: 1009/2Gb (49%)
#CPU load: 6.7%
#Last boot: 2024-01-15 14:45
#LVM use: yes
#Connections TCP : 1 ESTABLISHED
#User log: 1
#Network: IP 10.0.2.15 (08:00:27:51:9b:a5)
#Sudo : 127 cmd
```

## 🚀 Kurulum ve Çalıştırma

### 📋 **Ön Gereksinimler**
- VirtualBox
- Debian ISO (stable)
- Minimum 8GB disk space
- 2GB RAM

### ⚙️ **Kurulum Adımları**
1. **VirtualBox'ta yeni VM oluştur**
2. **Debian'ı encrypted LVM ile kur**
3. **Network ve SSH yapılandır**
4. **Security policies uygula**
5. **Monitoring script'i kur**
6. **Bonus servisleri ekle**

## 🧪 Test Edilenler

### 🔒 **Güvenlik Testleri**
- SSH connection (port 4242)
- Password policy enforcement
- Sudo logging functionality
- Firewall rule validation
- User permission management

### 📊 **Monitoring Testleri**
- Script accuracy validation
- Cron job scheduling
- System resource reporting
- Network information display

## 📚 Kullanılan Teknolojiler

![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat-square&logo=linux&logoColor=black)
![Debian](https://img.shields.io/badge/Debian-D70A53?style=flat-square&logo=debian&logoColor=white)
![VirtualBox](https://img.shields.io/badge/VirtualBox-183A61?style=flat-square&logo=virtualbox&logoColor=white)
![Shell Script](https://img.shields.io/badge/Shell_Script-121011?style=flat-square&logo=gnu-bash&logoColor=white)
![SSH](https://img.shields.io/badge/SSH-4D4D4D?style=flat-square&logo=openssh&logoColor=white)

## 🎖️ Proje Başarıları

- **Perfect Score**: 125/100 (Bonus included)
- **Security Implementation**: Enterprise-level hardening
- **Automation**: Efficient monitoring system
- **Documentation**: Comprehensive setup guide
- **Problem Solving**: Multiple troubleshooting scenarios handled

---

<div align="center">

### 👨‍💻 Created by Sude Naz Karayıldırım

[![42 Profile](https://img.shields.io/badge/42%20Profile-skarayil-black?style=flat-square&logo=42&logoColor=white)](https://profile.intra.42.fr/users/skarayil)
[![GitHub](https://img.shields.io/badge/GitHub-skarayil-181717?style=flat-square&logo=github&logoColor=white)](https://github.com/skarayil)

**⭐ Eğer bu proje işinize yaradıysa, repo'ya star vermeyi unutmayın!**

</div>
