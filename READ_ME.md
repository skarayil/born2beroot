# 🖥️ Born2beRoot - Kapsamlı Teorik Rehber

<div align="center">

![42 School](https://img.shields.io/badge/School-42-black?style=flat-square&logo=42)
![Linux](https://img.shields.io/badge/OS-Linux-informational?style=flat-square&logo=linux&logoColor=white)
![Debian](https://img.shields.io/badge/Debian-12-red?style=flat-square&logo=debian)
![Rocky Linux](https://img.shields.io/badge/Rocky%20Linux-9-green?style=flat-square&logo=rockylinux)
![VirtualBox](https://img.shields.io/badge/VirtualBox-6.1+-blue?style=flat-square&logo=virtualbox)

**Sistem yönetimi temellerini öğrenmek için tasarlanmış kapsamlı bir rehber**

[Özellikler](#-özellikler) • [Kurulum](#-kurulum) • [Konfigürasyon](#-konfigürasyon) • [Defense Hazırlığı](#-defense-hazırlığı) • [Troubleshooting](#-troubleshooting)

</div>

---

## 📋 İçerik

- [🎯 Proje Genel Bakış](#-proje-genel-bakış)
- [✨ Özellikler](#-özellikler)
- [🏗️ Mimari](#️-mimari)
- [⚙️ Kurulum](#️-kurulum)
- [🔧 Konfigürasyon](#-konfigürasyon)
- [🛡️ Güvenlik Uygulaması](#️-güvenlik-uygulaması)
- [📊 Monitoring Sistemi](#-monitoring-sistemi)
- [🎁 Bonus Özellikler](#-bonus-özellikler)
- [🔍 Defense Hazırlığı](#-defense-hazırlığı)
- [🚨 Troubleshooting](#-troubleshooting)
- [📝 Final Checklist](#-final-checklist)

---

## 🎯 Proje Genel Bakış

Born2beRoot, sistem yönetimi temellerini öğrenmek için tasarlanmış bir projedir. Sanal makine üzerinde Linux server kurulumu yaparak, güvenlik, kullanıcı yönetimi ve sistem izleme konularında deneyim kazanacaksın.

### 🎓 Öğrenme Hedefleri

- 🖥️ **Virtualization temelleri** VirtualBox/UTM ile
- 🐧 **Linux sistem yönetimi** (Debian/Rocky Linux)
- 🔐 **Güvenlik sıkılaştırma** ve erişim kontrolü
- 👥 **Kullanıcı yönetimi** ve izin sistemleri
- 🌐 **Network güvenliği** SSH ve firewall ile
- 📊 **Sistem monitoring** ve otomasyon
- 🛡️ **Mandatory Access Control** (AppArmor/SELinux)

---

## ✨ Özellikler

### 🔒 Güvenlik Özellikleri
- **Tam disk şifrelemesi** LUKS ile
- **Özel SSH konfigürasyonu** port 4242'de
- **Güçlü şifre politikası** PAM ile
- **Sudo kısıtlamaları** detaylı loglama ile
- **Firewall koruması** UFW/FirewallD ile
- **AppArmor/SELinux** mandatory access control

### 💾 Depolama Yönetimi
- **LVM (Logical Volume Manager)** esnek disk yönetimi için
- **Çoklu şifrelenmiş bölümler** sistem ayrımı için
- **Dinamik volume boyutlandırma** yetenekleri

### 📊 Monitoring ve Otomasyon
- **Gerçek zamanlı sistem monitoring** scripti
- **Otomatik raporlama** her 10 dakikada bir
- **Kapsamlı sistem istatistikleri** gösterimi
- **Cron job otomasyonu**

---

## 🏗️ Mimari

```
┌─────────────────────────────────────────────────────────────┐
│                    HOST MACHINE                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                VIRTUAL MACHINE                        │  │
│  │  ┌─────────────────────────────────────────────────┐  │  │
│  │  │            DEBIAN/ROCKY LINUX                   │  │  │
│  │  │  ┌─────────────────────────────────────────┐    │  │  │
│  │  │  │           ENCRYPTED LVM                 │    │  │  │
│  │  │  │  ├── root (/)                          │    │  │  │
│  │  │  │  ├── swap                              │    │  │  │
│  │  │  │  ├── home (/home)                      │    │  │  │
│  │  │  │  ├── var (/var)                        │    │  │  │
│  │  │  │  ├── srv (/srv)                        │    │  │  │
│  │  │  │  ├── tmp (/tmp)                        │    │  │  │
│  │  │  │  └── var-log (/var/log)                │    │  │  │
│  │  │  └─────────────────────────────────────────┘    │  │  │
│  │  └─────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### 🛡️ Güvenlik Katmanları (Defense in Depth)

```
┌─────────────────────────────────────┐
│          Disk Encryption            │ ← LUKS Full Disk Encryption
├─────────────────────────────────────┤
│         Firewall (UFW)              │ ← Network Level Security  
├─────────────────────────────────────┤
│      SSH Hardening (Port 4242)      │ ← Secure Remote Access
├─────────────────────────────────────┤
│    Mandatory Access Control         │ ← AppArmor/SELinux
├─────────────────────────────────────┤
│      Strong Password Policy         │ ← PAM + pwquality
├─────────────────────────────────────┤
│         Sudo Restrictions           │ ← Privilege Escalation Control
├─────────────────────────────────────┤
│       User Access Control          │ ← Groups + Permissions
├─────────────────────────────────────┤
│      System Monitoring             │ ← Real-time Surveillance
└─────────────────────────────────────┘
```

---

## ⚙️ Kurulum

### 📋 Ön Gereksinimler

- **VirtualBox** 6.1+ veya **UTM** (Apple Silicon için)
- **Debian 12** (Bookworm) veya **Rocky Linux 9** ISO'su
- Minimum **1GB RAM** ve **8GB depolama**

### 🚀 Hızlı Başlangıç

1. **Virtual Machine Oluştur**
   ```bash
   # ISO indir
   wget https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-12.2.0-amd64-netinst.iso
   
   # VM Ayarları
   RAM: 1024MB (önerilen: 2048MB)
   Depolama: 8GB (önerilen: 12GB)
   Network: NAT
   ```

2. **İşletim Sistemi Kur**
   - ⚠️ **Grafik arayüz yok** (zorunlu gereksinim)
   - **Disk şifrelemeyi** etkinleştir (LUKS)
   - **LVM partitioning** yapılandır
   - Hostname ayarla: `[login_adın]42`

3. **Temel Sistem Kurulumu**
   ```bash
   # Sistemi güncelle
   sudo apt update && sudo apt upgrade -y
   
   # Gerekli paketleri yükle
   sudo apt install openssh-server sudo ufw -y
   ```

---

## 🔧 Konfigürasyon

### 👥 Kullanıcı Yönetimi

```bash
# Kullanıcı ve grupları oluştur
sudo adduser [kullanici_adi]
sudo groupadd user42
sudo usermod -aG sudo,user42 [kullanici_adi]

# Grupları doğrula
groups [kullanici_adi]
id [kullanici_adi]
```

### 🔐 SSH Konfigürasyonu

`/etc/ssh/sshd_config` dosyasını düzenle:
```bash
Port 4242
PermitRootLogin no
PasswordAuthentication yes
PermitEmptyPasswords no
MaxAuthTries 3
```

SSH servisini yeniden başlat:
```bash
sudo systemctl restart ssh
sudo systemctl enable ssh
```

### 🔥 Firewall Kurulumu

```bash
# UFW'yi yapılandır
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 4242/tcp
sudo ufw enable

# Durumu kontrol et
sudo ufw status numbered
```

### 🔑 Şifre Politikası

`/etc/login.defs` yapılandır:
```bash
PASS_MAX_DAYS   30
PASS_MIN_DAYS   2
PASS_WARN_AGE   7
```

`/etc/security/pwquality.conf` yapılandır:
```bash
minlen = 10
dcredit = -1
ucredit = -1
lcredit = -1
maxrepeat = 3
reject_username
difok = 7
enforce_for_root
```

Mevcut kullanıcılara uygula:
```bash
sudo chage -M 30 -m 2 -W 7 [kullanici_adi]
sudo chage -M 30 -m 2 -W 7 root
```

---

## 🛡️ Güvenlik Uygulaması

### 🔐 Sudo Konfigürasyonu

`/etc/sudoers.d/sudo_config` oluştur:
```bash
Defaults passwd_tries=3
Defaults badpass_message="Yanlış şifre, tekrar deneyin!"
Defaults logfile="/var/log/sudo/sudo.log"
Defaults log_input,log_output
Defaults iolog_dir="/var/log/sudo"
Defaults requiretty
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
```

Log dizinini oluştur:
```bash
sudo mkdir -p /var/log/sudo
```

### 🛡️ AppArmor/SELinux

**Debian için (AppArmor):**
```bash
sudo systemctl enable apparmor
sudo systemctl start apparmor
sudo apparmor_status
```

**Rocky Linux için (SELinux):**
```bash
# Durumu kontrol et
sestatus

# /etc/selinux/config dosyasında enforcing modunu sağla
SELINUX=enforcing
SELINUXTYPE=targeted
```

---

## 📊 Monitoring Sistemi

### 📈 Monitoring Scripti

`/root/monitoring.sh` oluştur:

<details>
<summary>Monitoring script kodunu görmek için tıklayın</summary>

```bash
#!/bin/bash

# Born2beroot System Monitoring Script
echo "╔══════════════════════════════════════╗"
echo "║        SYSTEM MONITORING INFO        ║"
echo "╚══════════════════════════════════════╝"

# Architecture
arch=$(uname -a)
echo "#Architecture: $arch"

# CPU bilgisi
pcpu=$(grep "physical id" /proc/cpuinfo | sort -u | wc -l)
vcpu=$(grep -c ^processor /proc/cpuinfo)
echo "#CPU physical: $pcpu"
echo "#vCPU: $vcpu"

# Memory kullanımı
memory_usage=$(free -m | awk 'NR==2{printf "%s/%sMB (%.2f%%)", $3,$2,$3*100/$2}')
echo "#Memory Usage: $memory_usage"

# Disk kullanımı
disk_usage=$(df -BG | grep '^/dev/' | awk '{used += $3; total += $2} END {printf "%dG/%dG (%d%%)", used, total, used/total*100}')
echo "#Disk Usage: $disk_usage"

# CPU load
cpu_load=$(vmstat 1 2 | tail -1 | awk '{printf "%.1f%%", 100-$15}')
echo "#CPU load: $cpu_load"

# Son boot
last_boot=$(who -b | awk '{print $3, $4}')
echo "#Last boot: $last_boot"

# LVM kullanımı
if [ $(lsblk | grep "lvm" | wc -l) -eq 0 ]; then
    lvm_use="no"
else
    lvm_use="yes"
fi
echo "#LVM use: $lvm_use"

# TCP bağlantıları
tcp_conn=$(ss -ta | grep ESTAB | wc -l)
echo "#Connections TCP: $tcp_conn ESTABLISHED"

# Aktif kullanıcılar
user_log=$(who | wc -l)
echo "#User log: $user_log"

# Network bilgisi
ip_addr=$(hostname -I | awk '{print $1}')
mac_addr=$(ip link show | grep "link/ether" | awk '{print $2}' | head -n1)
echo "#Network: IP $ip_addr ($mac_addr)"

# Sudo komut sayısı
if [ -f "/var/log/sudo/sudo.log" ]; then
    sudo_cmd=$(grep -c "COMMAND" /var/log/sudo/sudo.log 2>/dev/null || echo "0")
else
    sudo_cmd=$(grep -c "sudo.*COMMAND" /var/log/auth.log 2>/dev/null || echo "0")
fi
echo "#Sudo: $sudo_cmd cmd"
```

</details>

### ⏰ Cron Job Kurulumu

```bash
# Script'i çalıştırılabilir yap
sudo chmod +x /root/monitoring.sh

# Crontab'a ekle
sudo crontab -e
# Bu satırı ekle:
*/10 * * * * /root/monitoring.sh | wall
```

### 📊 Örnek Çıktı

```
Broadcast message from root@kullanici42 (pts/0) (Wed Oct 25 15:30:01 2023):

╔══════════════════════════════════════╗
║        SYSTEM MONITORING INFO        ║
╚══════════════════════════════════════╝
#Architecture: Linux kullanici42 5.10.0-18-amd64 #1 SMP Debian x86_64 GNU/Linux
#CPU physical: 1
#vCPU: 1
#Memory Usage: 156/987MB (15.81%)
#Disk Usage: 2G/8G (25%)
#CPU load: 12.5%
#Last boot: 2023-10-25 14:30
#LVM use: yes
#Connections TCP: 3 ESTABLISHED
#User log: 1
#Network: IP 10.0.2.15 (08:00:27:51:9b:a5)
#Sudo: 42 cmd
```

---

## 🎁 Bonus Özellikler

### 🌐 WordPress Kurulumu

<details>
<summary>WordPress kurulum adımlarını görmek için tıklayın</summary>

1. **Lighttpd Kur**
   ```bash
   sudo apt install lighttpd
   sudo systemctl enable lighttpd
   ```

2. **MariaDB Kur**
   ```bash
   sudo apt install mariadb-server
   sudo mysql_secure_installation
   
   # WordPress veritabanı oluştur
   sudo mysql -u root -p
   CREATE DATABASE wordpress;
   CREATE USER 'wpuser'@'localhost' IDENTIFIED BY 'password';
   GRANT ALL PRIVILEGES ON wordpress.* TO 'wpuser'@'localhost';
   FLUSH PRIVILEGES;
   EXIT;
   ```

3. **PHP Kur**
   ```bash
   sudo apt install php-fpm php-mysql php-curl php-gd php-xml
   ```

4. **WordPress Kur**
   ```bash
   cd /var/www/html
   sudo wget https://wordpress.org/latest.tar.gz
   sudo tar -xzf latest.tar.gz
   sudo chown -R www-data:www-data wordpress/
   ```

5. **Firewall Yapılandır**
   ```bash
   sudo ufw allow 80/tcp
   sudo ufw allow 443/tcp
   ```

</details>

### 🔒 Ek Güvenlik Servisi

**Fail2ban Uygulaması:**
```bash
# Fail2ban kur
sudo apt install fail2ban

# SSH koruması yapılandır
sudo nano /etc/fail2ban/jail.local
```

Konfigürasyon ekle:
```ini
[sshd]
enabled = true
port = 4242
maxretry = 3
bantime = 600
findtime = 600
```

---

## 🔍 Defense Hazırlığı

### 📚 Öğrenilmesi Gereken Temel Konular

| Konu | Önemli Noktalar |
|------|-----------------|
| **Virtual Machine** | Hypervisor, izolasyon, kaynak paylaşımı |
| **LVM** | Physical Volumes, Volume Groups, Logical Volumes |
| **SSH** | Port 4242, key-based auth, güvenlik sıkılaştırma |
| **Firewall** | UFW kuralları, default politikalar, port yönetimi |
| **Sudo** | Privilege escalation, loglama, güvenlik politikaları |
| **Password Policy** | PAM, karmaşıklık gereksinimleri, aging |
| **AppArmor/SELinux** | Mandatory Access Control, profiller/contexts |

### 🎯 Yaygın Defense Soruları

<details>
<summary>Defense sorularını ve cevaplarını görmek için tıklayın</summary>

**S: Virtual Machine nedir ve nasıl çalışır?**
**C:** VM, fiziksel donanım üzerinde hypervisor aracılığıyla çalışan ve farklı işletim sistemleri için izole ortamlar sağlayan yazılım tabanlı bir bilgisayardır.

**S: Debian ve Rocky Linux arasındaki farklar nelerdir?**
**C:** Debian community-driven, APT paket yöneticisi ve AppArmor güvenliği kullanır, Rocky ise RHEL klonu olup YUM/DNF ve SELinux kullanır.

**S: Root login yerine neden sudo kullanılır?**
**C:** Sudo, loglama ve denetim ile geçici yetki yükseltmesi sağlar, daha iyi güvenlik için en az yetki prensibini takip eder.

**S: LVM nedir ve avantajları nelerdir?**
**C:** Logical Volume Manager, dinamik yeniden boyutlandırma, snapshot'lar ve birden fazla disk birleştirme gibi özelliklerle esnek disk yönetimi sağlar.

</details>

### 🔧 Defense Komutları

```bash
# Sistem Bilgileri
uname -a
hostnamectl
lsblk

# Kullanıcı Yönetimi Demo
sudo adduser testuser
sudo usermod -aG user42 testuser
groups testuser

# Şifre Politikası Testi
sudo chage -l testuser
passwd testuser

# Firewall Demo
sudo ufw status numbered
sudo ufw allow 8080
sudo ufw delete allow 8080

# LVM Bilgileri
sudo vgs
sudo lvs
sudo pvs

# Monitoring Script
sudo /root/monitoring.sh
sudo crontab -l
```

---

## 🚨 Troubleshooting

### 🔧 Yaygın Sorunlar

<details>
<summary>SSH Bağlantı Sorunları</summary>

```bash
# SSH servisini kontrol et
sudo systemctl status ssh

# Port dinlemesini kontrol et
sudo ss -tlnp | grep :4242

# Firewall'ı kontrol et
sudo ufw status

# SSH'ı yeniden başlat
sudo systemctl restart ssh
```

</details>

<details>
<summary>Şifre Politikası Sorunları</summary>

```bash
# Şifre kalitesini test et
echo "testpass" | pwscore

# Şifre aging'i kontrol et
sudo chage -l kullanici_adi

# PAM konfigürasyonunu doğrula
sudo pamtester login kullanici_adi authenticate
```

</details>

<details>
<summary>Sudo Sorunları</summary>

```bash
# Sudo konfigürasyonunu kontrol et
sudo visudo -c

# Sudo loglarını görüntüle
sudo tail /var/log/sudo/sudo.log
sudo tail /var/log/auth.log

# Sudo izinlerini test et
sudo -l
```

</details>

### 📋 Önemli Log Dosyaları

| Log Dosyası | Amacı |
|-------------|-------|
| `/var/log/auth.log` | Kimlik doğrulama denemeleri |
| `/var/log/sudo/sudo.log` | Sudo komut loglaması |
| `/var/log/ufw.log` | Firewall aktivitesi |
| `/var/log/cron.log` | Cron job çalıştırmaları |
| `/var/log/syslog` | Genel sistem mesajları |

---

## 📝 Final Checklist

### ✅ Zorunlu Gereksinimler

- [ ] **VM Kurulumu**
  - [ ] VirtualBox/UTM ile Debian/Rocky
  - [ ] Grafik arayüz yok
  - [ ] Minimum 2 şifrelenmiş LVM bölümü
  - [ ] Hostname: `[login]42`

- [ ] **Güvenlik Konfigürasyonu**
  - [ ] SSH port 4242'de
  - [ ] Root SSH login devre dışı
  - [ ] UFW firewall aktif (sadece port 4242 açık)
  - [ ] Güçlü şifre politikası uygulandı
  - [ ] AppArmor/SELinux aktif

- [ ] **Kullanıcı Yönetimi**
  - [ ] Root olmayan kullanıcı oluşturuldu
  - [ ] Kullanıcı user42 ve sudo gruplarında
  - [ ] Sudo konfigürasyonu tamamlandı
  - [ ] Şifre aging kuralları uygulandı

- [ ] **Monitoring Sistemi**
  - [ ] monitoring.sh scripti çalışıyor
  - [ ] Cron job her 10 dakikada çalışıyor
  - [ ] Wall komutu ile broadcast yapılıyor
  - [ ] Tüm gerekli bilgiler gösteriliyor

### ✅ Bonus Gereksinimler (İsteğe Bağlı)

- [ ] **Web Server**
  - [ ] WordPress kuruldu
  - [ ] Lighttpd + MariaDB + PHP çalışıyor
  - [ ] Bonus partitioning yapıldı

- [ ] **Ek Servis**
  - [ ] Fail2ban kuruldu ve yapılandırıldı
  - [ ] Gerekli portlar firewall'da açıldı

### 🎯 Son Kontrol Listesi - Defense Öncesi

⚡ **5 Dakikalık Hız Kontrol:**
```bash
# 1. Sistem bilgileri
uname -a && hostnamectl && lsblk

# 2. Kullanıcı ve grup kontrol  
id $(whoami) && groups $(whoami) && getent group user42

# 3. SSH ve Firewall
sudo systemctl status ssh && sudo ufw status

# 4. Şifre politikası test
sudo chage -l $(whoami)

# 5. Sudo konfigürasyon
sudo visudo -c && sudo -l

# 6. Güvenlik modülleri
sudo apparmor_status || sestatus

# 7. Monitoring script
sudo /root/monitoring.sh

# 8. Cron job
sudo crontab -l
```

### 🚨 Kritik Hatırlatmalar

1. **SNAPSHOT YASAK** - Defense sırasında kontrol edilir
2. **VM'İ GIT'E YÜKLEME** - Sadece signature.txt yükle
3. **ROOT LOGIN** - SSH ile root girişi kapatılmalı
4. **PORT 4242** - SSH sadece bu portta çalışmalı
5. **PASSWORD POLICY** - Tüm kullanıcılar için geçerli olmalı
6. **CRON JOB** - 10 dakikada bir çalışmalı
7. **FIREWALL** - Sadece 4242 portu açık olmalı
8. **LVM** - En az 2 şifrelenmiş bölüm olmalı

---

## 🏆 Başarı Garantisi

Bu checklist'i tamamen tamamladıysanız:
- ✅ **%100 Mandatory part tamamlanmış**
- ✅ **Defense'da tüm sorular cevaplanabilir**
- ✅ **Pratik gösterimler yapılabilir**
- ✅ **Troubleshooting yapılabilir**
- ✅ **Bonus point alınabilir**

**Son Tavsiye:** Defense öncesi tüm listeyi bir kez daha gözden geçirin ve her maddeyi test edin. Başarılar! 🚀🎓

---

<div align="center">

**📝 Not:** Bu rehber 42 öğrencileri için hazırlanmış kapsamlı bir kılavuzdur. Defense sırasında karşılaşabileceğiniz tüm soruların cevapları ve pratik komutları burada bulabilirsiniz.

</div>
