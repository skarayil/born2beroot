# 🗺️ Born2beRoot - Yol Haritası ve Yapılacaklar Listesi

<div align="center">

![42 School](https://img.shields.io/badge/School-42-black?style=for-the-badge&logo=42)
![System Admin](https://img.shields.io/badge/System-Administration-blue?style=for-the-badge&logo=linux&logoColor=white)
![Version](https://img.shields.io/badge/Version-3.6-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Complete%20Guide-success?style=for-the-badge)

**Sistem yönetimi ve güvenlik temellerini öğretmeyi amaçlayan kapsamlı proje rehberi**

*Sanal makine üzerinde minimum service ile güvenli bir server kurulumu yapacaksınız*

[Ön Hazırık](#-ön-hazırık) • [VM Kurulumu](#-adım-1-sanal-makine-kurulumu) • [Güvenlik](#️-adım-3-güvenlik-yapılandırması) • [Monitoring](#-adım-4-monitoring-script) • [Defense](#-test-ve-sunum-hazırlığı)

</div>

---

## 🎯 Proje Genel Bakış - Version 3.6

<img align="right" alt="System Admin" width="300" src="https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExZXZvMTJuNWYzZzJ5YmZvemM3cnN5dDlwMDE0cW1yazdzNzZpaXEwNSZlcD12MV9naWZzX3NlYXJjaCZjdD1n/NOGKeoGHEQVgY/giphy.gif">

Born2beroot, **sistem yönetimi ve güvenlik temellerini** öğretmeyi amaçlayan bir projedir. Sanal makine üzerinde minimum service ile güvenli bir server kurulumu yapacaksınız.

### ⚠️ **KRİTİK UYARI**
> **Hiçbir grafik arayüz (X.org vb.) kurulmayacak - aksi halde 0 puan!**

### 🎓 **Öğrenme Hedefleri**
- Virtual Machine yönetimi
- Linux sistem yönetimi
- Network güvenliği (SSH, Firewall)
- User ve permission management
- System monitoring ve automation
- Security hardening techniques

---

## 📚 Ön Hazırık (Başlamadan Önce Öğrenilecekler)

### 🧠 **Temel Kavramlar**

<div align="center">

![Virtual Machine](https://img.shields.io/badge/Concept-Virtual%20Machine-blue?style=flat-square)
![Linux](https://img.shields.io/badge/Concept-Linux%20Distributions-green?style=flat-square)
![Security](https://img.shields.io/badge/Concept-System%20Security-red?style=flat-square)

</div>

| Kavram | Açıklama | Neden Önemli |
|--------|----------|--------------|
| **Sanal Makine** | Fiziksel bilgisayar üzerinde çalışan sanal bilgisayar | İzolasyon ve güvenlik |
| **Linux Dağıtımları** | Debian vs Rocky Linux farkları | Doğru araç seçimi |
| **Root vs Normal User** | Yetki seviyeleri ve güvenlik | Least privilege principle |
| **SSH** | Uzaktan güvenli bağlantı protokolü | Secure remote access |
| **Firewall** | Ağ güvenliği ve port kontrolü | Network security |

### 🔧 **Öğrenilecek Komutlar**

#### 📊 **Sistem Bilgisi**
```bash
uname -a              # Kernel ve sistem bilgisi
hostnamectl           # Hostname yönetimi
lsb_release -a        # Dağıtım bilgisi
systemctl status      # Servis durumları
```

#### 👥 **Kullanıcı Yönetimi**
```bash
adduser [username]    # Kullanıcı ekleme
usermod -aG [group]   # Gruba ekleme
groups [username]     # Grup üyeliklerini görme
id [username]         # Kullanıcı ID bilgileri
su - [username]       # Kullanıcı değiştirme
sudo [command]        # Root yetkisi ile çalıştırma
```

#### 📁 **Dosya Sistemi**
```bash
ls -la               # Detaylı dosya listesi
chmod [permissions]  # İzin değiştirme
chown [user:group]   # Sahiplik değiştirme
df -h                # Disk kullanımı
lsblk                # Block device listesi
```

#### 🌐 **Ağ Yönetimi**
```bash
ip addr              # IP adresi bilgisi
ss -tuln             # Açık portlar
systemctl status ssh # SSH servis durumu
ufw status           # Firewall durumu
```

#### 📦 **Paket Yönetimi (Debian)**
```bash
apt update           # Paket listesi güncelleme
apt install [package] # Paket kurma
apt list --installed # Kurulu paketler
apt remove [package] # Paket kaldırma
```

---

## 🚀 ADIM 1: Sanal Makine Kurulumu

### 📋 **Yapılacaklar Listesi**

<div align="center">

![VirtualBox](https://img.shields.io/badge/VirtualBox-Installation-blue?style=for-the-badge&logo=virtualbox)
![Debian](https://img.shields.io/badge/Debian-Stable-red?style=for-the-badge&logo=debian)

</div>

#### 🔽 **1. VirtualBox Kurulumu**
- [ ] VirtualBox indirip kur
- [ ] Extension Pack kurulumu (isteğe bağlı)
- [ ] Host-only network adapter oluştur

#### 💿 **2. Debian ISO İndirme**
- [ ] Debian stable sürüm ISO dosyasını indir
- [ ] checksum kontrolü yap
- [ ] ISO dosyasını güvenli konuma kaydet

#### 🖥️ **3. Sanal Makine Oluşturma**

| Ayar | Minimum | Önerilen | Açıklama |
|------|---------|----------|----------|
| **RAM** | 1GB | 2GB | Smooth operation için |
| **Disk** | 8GB | 12GB | Güvenli alan için |
| **Network** | NAT | NAT + Host-only | SSH erişimi için |
| **CPU** | 1 core | 2 core | Performance için |

#### 🛠️ **4. Debian Kurulumu**

### ⚙️ **Kurulum Sırasında Dikkat Edilecekler**

| Gereksinim | Detay | Kritiklik |
|------------|-------|-----------|
| **Encryption** | En az 2 encrypted partition (LVM) | 🔴 Mandatory |
| **Grafik Arayüz** | Hiçbir desktop environment kurma | 🔴 ZERO POINT |
| **Root Password** | Güçlü password belirle | 🟡 Security |
| **User Creation** | `login42` formatında (örn: sudenaz42) | 🔴 Mandatory |
| **SSH Server** | Kurulum sırasında seç | 🟡 Required |
| **AppArmor** | Startup'ta aktif olmalı (Debian) | 🟡 Required |
| **Minimal Setup** | Sadece base system kurulumu | 🔴 Important |

---

## 🔧 ADIM 2: Temel Sistem Yapılandırması

### 🏷️ **Hostname ve Network**

```bash
# Hostname ayarlama (defense sırasında değiştireceksin)
sudo hostnamectl set-hostname sudenaz42

# SSH port yapılandırması (port 4242)
sudo nano /etc/ssh/sshd_config
# Port 4242
sudo systemctl restart ssh

# AppArmor durumu kontrol
sudo systemctl status apparmor
sudo aa-status
```

### 👤 **Kullanıcı Yönetimi**

```bash
# User'ı gerekli gruplara ekle
sudo usermod -aG user42,sudo sudenaz42

# Grup üyeliklerini kontrol et
groups sudenaz42
id sudenaz42

# Root SSH login'i devre dışı bırak
sudo nano /etc/ssh/sshd_config
# PermitRootLogin no

# SSH servisini yeniden başlat
sudo systemctl restart ssh
```

### ✅ **Defense Hazırlık Notu**
> Defense sırasında yeni user oluşturup gruba ekleme testi olacak!

---

## 🛡️ ADIM 3: Güvenlik Yapılandırması

### 🔐 **Password Policy (Çok Spesifik!)**

<div align="center">

![Security Policy](https://img.shields.io/badge/Security-Password%20Policy-red?style=for-the-badge&logo=shield)

</div>

#### 📝 **Policy Gereksinimleri**

| Kural | Değer | Dosya | Açıklama |
|-------|-------|-------|----------|
| **Password Expiry** | 30 gün | `/etc/login.defs` | PASS_MAX_DAYS |
| **Min Days Before Change** | 2 gün | `/etc/login.defs` | PASS_MIN_DAYS |
| **Warning Before Expiry** | 7 gün | `/etc/login.defs` | PASS_WARN_AGE |
| **Minimum Length** | 10 karakter | `/etc/security/pwquality.conf` | minlen |
| **Uppercase Required** | 1 harf | `/etc/security/pwquality.conf` | ucredit |
| **Lowercase Required** | 1 harf | `/etc/security/pwquality.conf` | lcredit |
| **Digit Required** | 1 rakam | `/etc/security/pwquality.conf` | dcredit |
| **Max Consecutive** | 3 karakter | `/etc/security/pwquality.conf` | maxrepeat |
| **Username Check** | Yasak | `/etc/security/pwquality.conf` | reject_username |
| **Different from Old** | 7 karakter | `/etc/security/pwquality.conf` | difok |

#### 🔧 **Implementation Commands**

<details>
<summary><strong>Password Policy Configuration</strong></summary>

```bash
# /etc/login.defs düzenleme
sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t30/' /etc/login.defs
sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t2/' /etc/login.defs
sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE\t7/' /etc/login.defs

# /etc/security/pwquality.conf yapılandırması
echo "minlen = 10" >> /etc/security/pwquality.conf
echo "ucredit = -1" >> /etc/security/pwquality.conf
echo "lcredit = -1" >> /etc/security/pwquality.conf
echo "dcredit = -1" >> /etc/security/pwquality.conf
echo "maxrepeat = 3" >> /etc/security/pwquality.conf
echo "reject_username" >> /etc/security/pwquality.conf
echo "difok = 7" >> /etc/security/pwquality.conf
echo "enforce_for_root" >> /etc/security/pwquality.conf

# Mevcut kullanıcılar için password aging
sudo chage -M 30 -m 2 -W 7 sudenaz42
sudo chage -M 30 -m 2 -W 7 root
```

</details>

### 🔐 **Sudo Yapılandırması (/etc/sudoers) - Çok Spesifik!**

#### 📋 **Sudo Gereksinimleri**

| Konfigürasyon | Değer | Açıklama |
|---------------|-------|----------|
| **Max Attempts** | 3 deneme | passwd_tries=3 |
| **Custom Error** | Özel mesaj | badpass_message |
| **Logging** | Input/Output | log_input,log_output |
| **Log Directory** | `/var/log/sudo/` | logfile, iolog_dir |
| **TTY Requirement** | Aktif | requiretty |
| **Secure Path** | Restricted PATH | secure_path |

#### ⚙️ **Sudo Configuration**

```bash
# Sudo config dosyası oluştur
sudo visudo -f /etc/sudoers.d/sudo_config

# İçerik:
Defaults passwd_tries=3
Defaults badpass_message="Access denied! Please check your credentials."
Defaults logfile="/var/log/sudo/sudo.log"
Defaults log_input,log_output
Defaults iolog_dir="/var/log/sudo"
Defaults requiretty
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"

# Log dizinini oluştur
sudo mkdir -p /var/log/sudo
```

### 🌐 **SSH Güvenliği (/etc/ssh/sshd_config)**

```bash
# SSH yapılandırması
sudo nano /etc/ssh/sshd_config

# Değiştirilecek ayarlar:
Port 4242
PermitRootLogin no
PasswordAuthentication yes
PermitEmptyPasswords no
MaxAuthTries 3

# SSH servisini yeniden başlat
sudo systemctl restart ssh
sudo systemctl enable ssh
```

### 🔥 **Firewall (UFW)**

```bash
# UFW kurulumu ve yapılandırması
sudo apt install ufw

# Default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# SSH portunu aç
sudo ufw allow 4242/tcp

# UFW'yi aktif et
sudo ufw enable

# Status kontrolü
sudo ufw status numbered
```

---

## 📊 ADIM 4: Monitoring Script

### 📝 **Script Gereksinimleri (monitoring.sh) - EXACT FORMAT**

<div align="center">

![Monitoring](https://img.shields.io/badge/Monitoring-System%20Stats-green?style=for-the-badge&logo=grafana)

</div>

#### 📋 **Gösterilecek Bilgiler (Sırasıyla)**

| No | Bilgi | Komut/Kaynak | Format |
|----|-------|--------------|--------|
| 1 | **Architecture** | `uname -a` | Full system info |
| 2 | **CPU Physical** | `/proc/cpuinfo` | Physical processor count |
| 3 | **vCPU** | `/proc/cpuinfo` | Virtual processor count |
| 4 | **Memory Usage** | `free` | Used/Total MB (%) |
| 5 | **Disk Usage** | `df` | Used/Total (%) |
| 6 | **CPU Load** | `vmstat` | Processor load % |
| 7 | **Last Boot** | `who -b` | Last restart date/time |
| 8 | **LVM Use** | `lsblk` | yes/no |
| 9 | **TCP Connections** | `ss` | ESTABLISHED count |
| 10 | **User Log** | `who` | Logged in user count |
| 11 | **Network** | `hostname -I` + `ip link` | IP + MAC address |
| 12 | **Sudo** | Log files | Total sudo command count |

#### 📄 **Örnek Çıktı Formatı**

```text
#Architecture: Linux wil 4.19.0-16-amd64 #1 SMP Debian 4.19.181-1 (2021-03-19) x86_64 GNU/Linux
#CPU physical : 1
#vCPU : 1
#Memory Usage: 74/987MB (7.50%)
#Disk Usage: 1009/2Gb (49%)
#CPU load: 6.7%
#Last boot: 2021-04-25 14:45
#LVM use: yes
#Connections TCP : 1 ESTABLISHED
#User log: 1
#Network: IP 10.0.2.15 (08:00:27:51:9b:a5)
#Sudo : 42 cmd
```

### ⏰ **Cron Job Yapılandırması**

```bash
# Script'i oluştur
sudo nano /root/monitoring.sh
sudo chmod +x /root/monitoring.sh

# Cron job ekle
sudo crontab -e
# */10 * * * * /root/monitoring.sh | wall

# Cron servisini kontrol et
sudo systemctl status cron
sudo systemctl enable cron
```

#### 📌 **Cron Job Gereksinimleri**
- [ ] Her 10 dakikada çalışmalı
- [ ] Server startup'ta otomatik başlamalı
- [ ] Tüm terminallere broadcast (`wall` komutu)
- [ ] Defense sırasında durdurulabilmeli

---

## 🎁 BONUS KISIM - Sadece Mandatory Perfect İse!

<div align="center">

![Bonus](https://img.shields.io/badge/BONUS-Only%20If%20Perfect-gold?style=for-the-badge&logo=star)

</div>

### ⚠️ **UYARI**
> Bonus sadece mandatory kısım MÜKEMMEL ise değerlendirilir!

### 🗂️ **Partition Yapısı (Bonus)**

```
NAME                    SIZE TYPE  MOUNTPOINT
sda                    30.8G disk
├─sda1                  500M part  /boot
└─sda2                   1K part
  └─sda5               30.3G part
    └─sda5_crypt       30.3G crypt
      ├─LVMGroup-root  10G   lvm   /
      ├─LVMGroup-swap  2.3G  lvm   [SWAP]
      ├─LVMGroup-home  5G    lvm   /home
      ├─LVMGroup-var   3G    lvm   /var
      ├─LVMGroup-srv   3G    lvm   /srv
      ├─LVMGroup-tmp   3G    lvm   /tmp
      └─LVMGroup-var-log 4G  lvm   /var/log
```

### 🌐 **WordPress Stack**

| Komponet | Açıklama | Yasak |
|----------|----------|-------|
| **Lighttpd** | Web server | Apache/Nginx yasak! |
| **MariaDB** | Database server | MySQL alternatifi |
| **PHP** | Server-side scripting | WordPress için gerekli |
| **WordPress** | CMS kurulumu | Functional website |

### 🔧 **Ek Servis (Kendi Seçimin)**

#### 💡 **Bonus Servis Önerileri**

| Servis | Kategori | Fayda | Zorluk |
|--------|----------|-------|--------|
| **Fail2ban** | Güvenlik | Brute force protection | ⭐⭐ |
| **Netdata** | Monitoring | Real-time metrics | ⭐⭐⭐ |
| **vsftpd** | FTP Server | File transfer | ⭐⭐ |
| **Postfix** | Mail Server | Email handling | ⭐⭐⭐⭐ |
| **Gitea** | Git Server | Source control | ⭐⭐⭐ |

#### 📝 **Bonus Gereksinimler**
- [ ] Faydalı bir servis kur (NGINX/Apache2 hariç)
- [ ] Defense'da seçimini gerekçelendir
- [ ] Ek portlar açabilirsin (UFW kurallarını güncelle)

---

## ✅ Test ve Sunum Hazırlığı

### 🧪 **Sistem Testleri**

<div align="center">

![Testing](https://img.shields.io/badge/Testing-System%20Validation-blue?style=for-the-badge&logo=checkmark)

</div>

#### 🔍 **Pre-Defense Checklist**

| Test | Komut | Beklenen Sonuç |
|------|-------|----------------|
| **Servisler** | `systemctl status ssh ufw cron` | Active (running) |
| **Password Policy** | `chage -l username` | Policy settings |
| **SSH Connection** | `ssh user@localhost -p 4242` | Successful connection |
| **Sudo Logs** | `sudo tail /var/log/sudo/sudo.log` | Command logs |
| **Monitoring Script** | `/root/monitoring.sh` | Correct output |
| **Firewall Rules** | `sudo ufw status numbered` | Only 4242 open |
| **User Groups** | `groups username` | user42, sudo |
| **LVM Status** | `lsblk` | LVM partitions |

### 🎯 **Defense Hazırlığı - BİLMEN GEREKEN SORULAR**

<details>
<summary><strong>Subject'ta Belirtilen Kritik Sorular</strong></summary>

#### 🖥️ **Sistem ve Dağıtım**
- **Debian seçiminin nedeni nedir?**
  - Stability, security, large community
- **apt vs aptitude farkları nelerdir?**
  - Interface, dependency resolution, automation
- **Virtual Machine avantajları ve dezavantajları?**
  - Isolation vs performance overhead

#### 🔒 **Güvenlik**
- **AppArmor nedir ve nasıl çalışır?**
  - Mandatory Access Control, profile-based
- **SSH nasıl çalışır ve neden güvenlidir?**
  - Encryption, authentication, key exchange
- **UFW nedir ve nasıl yapılandırılır?**
  - Uncomplicated Firewall, iptables frontend

#### 👥 **Kullanıcı Yönetimi**
- **Sudo sistemi nasıl çalışır?**
  - Privilege escalation, temporary root access
- **Password policy neden önemlidir?**
  - Security best practices, attack prevention

#### 💾 **Disk Yönetimi**
- **LVM nedir ve avantajları?**
  - Logical Volume Manager, flexibility, snapshots

#### 🤖 **Monitoring**
- **Cron job nedir ve monitoring script nasıl çalışır?**
  - Time-based scheduler, automated tasks
- **Script'i nasıl durdurursun? (cron olmadan)**
  - `sudo systemctl stop cron`

</details>

### 🎭 **Defense Sırasında YAPILACAKLAR**

#### 📝 **Pratik Gösterimler**

| Görev | Komutlar | Amaç |
|-------|----------|------|
| **Yeni User Oluştur** | `sudo adduser testuser` | User management |
| **Gruba Ekle** | `sudo usermod -aG user42 testuser` | Group management |
| **Hostname Değiştir** | `sudo hostnamectl set-hostname newname` | System config |
| **SSH Bağlantısı** | `ssh testuser@localhost -p 4242` | Network access |
| **Script Durdur** | `sudo systemctl stop cron` | Service control |
| **UFW Rules** | `sudo ufw status numbered` | Security config |
| **Sudo Logs** | `sudo tail /var/log/sudo/sudo.log` | Security audit |

### 📺 **Sunum Sırasında Gösterilecekler**

#### 🔍 **Demonstration Commands**

```bash
# Hostname kontrolü
hostnamectl

# User ve group kontrolü
groups [username]
id [username]

# SSH servis durumu
systemctl status ssh

# UFW durumu
sudo ufw status numbered

# Password policy dosyaları
cat /etc/login.defs | grep PASS
cat /etc/security/pwquality.conf

# Sudo yapılandırması
sudo cat /etc/sudoers.d/sudo_config

# Cron jobs
sudo crontab -l

# Monitoring script çalışması
sudo /root/monitoring.sh

# LVM status
lsblk
sudo vgs
sudo lvs
```

---

## ⚠️ KRITIK UYARILAR - SIFIR PUAN ALMAMAK İÇİN!

<div align="center">

![Critical Warning](https://img.shields.io/badge/⚠️-CRITICAL%20WARNINGS-red?style=for-the-badge)

</div>

### 🚨 **Zero Point Scenarios**

| Durum | Sonuç | Önlem |
|-------|-------|-------|
| **Grafik Arayüz** | X.org kurulumu | → 0 puan |
| **Snapshot Kullanımı** | Detection | → 0 puan |
| **Yanlış Signature** | VM signature mismatch | → 0 puan |
| **Mandatory Eksik** | Bonus değerlendirilmez | → Bonus iptal |
| **VM Git Upload** | Repository'de VM dosyası | → Violation |

### ✅ **Success Criteria**

- [ ] Hiçbir grafik arayüz kurulmamış
- [ ] Snapshot kullanılmamış
- [ ] `signature.txt` doğru ve güncel
- [ ] Mandatory requirements %100 tamamlanmış
- [ ] Sadece signature.txt Git'e uploadlanmış

---

## 📁 Teslim (Submission)

### 📋 **Submission Checklist**

#### 1️⃣ **VM Signature Alma**

```bash
# Linux
sha1sum your_vm.vdi

# Windows
certUtil -hashfile your_vm.vdi sha1

# Mac (VirtualBox)
shasum your_vm.vdi

# Mac (UTM)
shasum your_vm.utm/Images/disk-0.qcow2
```

#### 2️⃣ **Signature.txt Oluşturma**

```bash
# Repository root dizininde
echo "6e657c4619944be17df3c31faa030c25e43e40af" > signature.txt
git add signature.txt
git commit -m "Add signature.txt"
git push
```

#### 3️⃣ **Final Validation**

- [ ] VM tamamen kapatıldı
- [ ] Signature alındı ve doğrulandı
- [ ] signature.txt dosyası oluşturuldu
- [ ] Sadece signature.txt Git'e pushlandı
- [ ] VM klonlandı (backup)

---

## 🔧 Troubleshooting - Yaygın Problemler

### 🌐 **SSH Bağlantı Problemleri**

<details>
<summary><strong>SSH Connection Issues</strong></summary>

```bash
# Port forwarding kontrolü (VirtualBox)
# Settings → Network → Advanced → Port Forwarding
# Host Port: 4242, Guest Port: 4242

# SSH config syntax kontrolü
sudo sshd -t

# SSH servis durumu
sudo systemctl status ssh
sudo systemctl restart ssh

# Firewall kontrolü
sudo ufw status
sudo ufw allow 4242/tcp
```

</details>

### 🔐 **Sudo Problemleri**

<details>
<summary><strong>Sudo Configuration Issues</strong></summary>

```bash
# Syntax kontrolü (GÜVENLİ)
sudo visudo -c

# User'ı sudo grubuna ekle
sudo usermod -aG sudo username

# Sudo config dosyası kontrol
sudo cat /etc/sudoers.d/sudo_config

# TTY requirement test
sudo -t echo "TTY test"
```

</details>

### 📊 **Script Problemleri**

<details>
<summary><strong>Monitoring Script Issues</strong></summary>

```bash
# Execute permission kontrol
ls -la /root/monitoring.sh
sudo chmod +x /root/monitoring.sh

# Script syntax test
bash -n /root/monitoring.sh

# Cron environment test
sudo crontab -l
sudo systemctl status cron

# Wall permission test
echo "Test message" | wall
```

</details>

---

## 💡 Önemli İpuçları

### 🛡️ **Best Practices**

<div align="center">

![Best Practices](https://img.shields.io/badge/💡-Best%20Practices-yellow?style=for-the-badge)

</div>

#### 📚 **Geliştirme Tavsiyeleri**

| Prensip | Açıklama | Fayda |
|---------|----------|-------|
| **Backup First** | Her değişiklik öncesi backup al | Recovery capability |
| **Step by Step** | Adım adım ilerle | Error isolation |
| **Log Monitoring** | `/var/log/` dosyalarını takip et | Problem diagnosis |
| **Test Everything** | Her yapılandırma sonrası test et | Quality assurance |
| **Document Changes** | Değişiklikleri not al | Knowledge retention |

#### 🔍 **Debug Strategies**

```bash
# Log monitoring
sudo tail -f /var/log/syslog
sudo tail -f /var/log/auth.log
sudo journalctl -f

# Service debugging
sudo systemctl status [service]
sudo systemctl restart [service]

# Network debugging
sudo ss -tuln
sudo netstat -tuln
```

---

## 📚 Faydalı Kaynaklar

### 📖 **Official Documentation**

| Kaynak | URL | Kategori |
|--------|-----|----------|
| **Debian Docs** | `https://www.debian.org/doc/` | OS Documentation |
| **UFW Manual** | `man ufw` | Firewall Guide |
| **SSH Config** | `man sshd_config` | SSH Configuration |
| **Crontab Guide** | `man crontab` | Task Scheduling |
| **42 Subject** | 42 Intra | Project Requirements |

### 🛠️ **Command References**

```bash
# Quick reference commands
man [command]              # Manual pages
info [command]             # Info documentation
[command] --help           # Help output
apropos [keyword]          # Search commands
which [command]            # Command location
```

### 🎓 **Learning Resources**

#### 📺 **Video Tutorials**
- System Administration basics
- Linux security hardening
- Virtual machine management
- Network configuration

#### 📝 **Practice Labs**
- VirtualBox/VMware tutorials
- Linux command line exercises
- Security configuration guides
- Monitoring script examples

---

## 🎖️ Proje Başarı Kriterleri

<div align="center">

![Achievement](https://img.shields.io/badge/🎯-Success%20Criteria-gold?style=for-the-badge)

### 📊 **Proje İstatistikleri**

| Kategori | Detay | Status |
|----------|-------|--------|
| **VM Configuration** | Debian + Encrypted LVM | ✅ Required |
| **Security Setup** | SSH + Firewall + Policies | ✅ Required |
| **User Management** | Groups + Permissions | ✅ Required |
| **Monitoring** | Script + Cron + Logging | ✅ Required |
| **Bonus Features** | WordPress + Extra Service | 🎁 Optional |
| **Defense Readiness** | Questions + Demonstrations | 📚 Critical |

</div>

### 🏆 **Başarı Seviyeleri**

| Seviye | Puan | Açıklama | Gereksinimler |
|--------|------|----------|---------------|
| **Basic Pass** | 80-99 | Mandatory tamamlandı | Tüm temel gereksinimler |
| **Perfect Score** | 100 | Flawless execution | Hata yok + clean presentation |
| **Bonus Achievement** | 125 | Extra mile | Perfect + bonus features |

---

## 🎯 Defense Stratejisi

### 📝 **Hazırlık Planı**

#### 🗓️ **Defense Öncesi Son Kontroller**

| Zaman | Aktivite | Kontrol Edilecekler |
|-------|----------|-------------------|
| **-24h** | Final Testing | Tüm sistemlerin çalışması |
| **-12h** | Backup Creation | VM klonlama |
| **-6h** | Question Review | Sorulara hazırlık |
| **-2h** | Clean Environment | Gereksiz dosya temizliği |
| **-1h** | Signature Update | Son signature alma |

#### 🎭 **Defense Sırasında Yaklaşım**

```bash
# Kendine güven göster
"Bu konfigürasyonu şu sebeplerle seçtim..."

# Teknik bilgi göster
"Bu komutun çıktısı şunu gösteriyor..."

# Problem solving
"Eğer bu hata olursa, şöyle çözerim..."

# Alternatif yaklaşımlar
"Bu işlem için alternatif yöntemler..."
```

### 🤝 **Evaluator ile İletişim**

#### ✅ **Do's**
- Net ve açık konuş
- Yaptığın her adımı açıkla
- Sorulara direkt cevap ver
- Bilmediğin şeyi kabul et
- Alternatif çözümler öner

#### ❌ **Don'ts**
- Panik yapma
- Yalan söyleme
- Çok hızlı geçme
- Sorulara kaçamak cevap verme
- Defense'ı sabote etme

---

## 🔄 Proje Sonrası Gelişim

### 📈 **Skill Development**

<div align="center">

![Skills](https://img.shields.io/badge/🎯-Skills%20Gained-blue?style=for-the-badge)

</div>

#### 💪 **Kazanılan Yetenekler**

| Kategori | Beceriler | Gelecek Kullanım |
|----------|-----------|------------------|
| **System Admin** | Linux, VM, Security | DevOps, SysAdmin roles |
| **Networking** | SSH, Firewall, Protocols | Network engineering |
| **Security** | Hardening, Policies, Monitoring | InfoSec, Compliance |
| **Automation** | Scripts, Cron, Monitoring | Automation engineer |
| **Troubleshooting** | Debug, Logs, Problem solving | Technical support |

#### 🚀 **Next Steps**

```bash
# Sonraki öğrenme alanları
- Docker ve Containerization
- Kubernetes orchestration
- Cloud platforms (AWS, Azure, GCP)
- Infrastructure as Code (Terraform)
- Configuration Management (Ansible)
- Monitoring tools (Prometheus, Grafana)
- CI/CD pipelines
```

### 🎓 **Career Path Options**

| Rol | Açıklama | Born2beRoot Bağlantısı |
|-----|----------|----------------------|
| **DevOps Engineer** | Development + Operations | Automation, monitoring |
| **System Administrator** | Server management | Linux, security, users |
| **Security Engineer** | Cybersecurity specialist | Hardening, policies |
| **Cloud Engineer** | Cloud infrastructure | VM concepts, networking |
| **Site Reliability Engineer** | Production systems | Monitoring, automation |

---

## 📞 Yardım ve Destek

### 🆘 **Acil Durum Rehberi**

<div align="center">

![Emergency](https://img.shields.io/badge/🆘-Emergency%20Guide-red?style=for-the-badge)

</div>

#### 🚨 **VM Crash Recovery**

```bash
# VM açılmıyor
1. VirtualBox logs kontrol et
2. Backuptan restore yap
3. Safe mode ile boot et
4. Filesystem check: fsck

# Network bağlantısı yok
1. Network adapter ayarlarını kontrol et
2. VirtualBox network resetle
3. Guest additions yeniden kur
4. IP konfigürasyonunu kontrol et
```

#### 🔧 **Son Dakika Problemleri**

| Problem | Hızlı Çözüm | Backup Plan |
|---------|--------------|-------------|
| **SSH çalışmıyor** | `systemctl restart ssh` | Console üzerinden düzelt |
| **Monitoring script hata** | Syntax kontrol + debug | Manuel run + fix |
| **Password policy çalışmıyor** | Config files kontrol | Reset + reapply |
| **Sudo çalışmıyor** | visudo syntax check | Root ile düzelt |

### 📧 **Topluluk Desteği**

#### 💬 **42 Community Resources**

- **Slack channels**: #born2beroot, #sysadmin
- **Study groups**: Peer learning sessions
- **42 Discord**: Real-time help
- **Intra forums**: Project discussions

#### 🌐 **External Resources**

- **Stack Overflow**: Technical questions
- **Reddit r/sysadmin**: Professional advice
- **Linux documentation**: Official guides
- **YouTube tutorials**: Visual learning

---

## 📋 Final Checklist

### ✅ **Pre-submission Validation**

<div align="center">

![Final Check](https://img.shields.io/badge/✅-Final%20Checklist-green?style=for-the-badge)

</div>

#### 🎯 **Mandatory Requirements**

- [ ] **VM Configuration**
  - [ ] Debian installed (no GUI)
  - [ ] Encrypted LVM partitions (minimum 2)
  - [ ] Hostname in login42 format
  - [ ] Strong passwords set

- [ ] **Security Setup**
  - [ ] SSH on port 4242
  - [ ] Root SSH disabled
  - [ ] UFW configured (only 4242 open)
  - [ ] Password policy implemented
  - [ ] Sudo rules configured

- [ ] **User Management**
  - [ ] User in user42 and sudo groups
  - [ ] Can create new users
  - [ ] Group management working

- [ ] **Monitoring**
  - [ ] Script shows all required info
  - [ ] Cron job runs every 10 minutes
  - [ ] Wall broadcasts working
  - [ ] Can stop/start cron

- [ ] **Documentation**
  - [ ] Signature.txt created
  - [ ] Only signature in repository
  - [ ] Defense questions prepared

#### 🎁 **Bonus Requirements (if applicable)**

- [ ] **Partition Structure**
  - [ ] Subject diagram implemented
  - [ ] All mount points correct

- [ ] **WordPress Stack**
  - [ ] Lighttpd running
  - [ ] MariaDB configured  
  - [ ] PHP working
  - [ ] WordPress accessible

- [ ] **Extra Service**
  - [ ] Service installed and running
  - [ ] Justified choice
  - [ ] Additional ports configured

### 🎊 **Success Celebration**

Tebrikler! Born2beRoot projesini tamamladınız! 🎉

Bu proje boyunca öğrendikleriniz:
- **System Administration** fundamentals
- **Linux Security** best practices  
- **Network Configuration** skills
- **Automation** techniques
- **Problem Solving** abilities

Artık bir **junior system administrator** seviyesinde bilgi sahibisiniz!

---

<div align="center">

### 🎯 **Core Skills Mastered**

![Linux](https://img.shields.io/badge/Linux-System%20Administration-green?style=flat-square&logo=linux)
![Security](https://img.shields.io/badge/Security-Hardening-red?style=flat-square&logo=shield)
![Networking](https://img.shields.io/badge/Networking-SSH%20%26%20Firewall-blue?style=flat-square&logo=cisco)
![Automation](https://img.shields.io/badge/Automation-Scripts%20%26%20Cron-orange?style=flat-square&logo=clockify)
![Monitoring](https://img.shields.io/badge/Monitoring-System%20Stats-purple?style=flat-square&logo=grafana)

---

**💻 "Born2beRoot taught you that with great power comes great responsibility."**

*Bu proje ile sistem yönetiminin temellerini öğrendiniz ve güvenli server kurma yeteneği kazandınız.*

---

### 👨‍💻 Created by Sude Naz Karayıldırım

[![42 Profile](https://img.shields.io/badge/42%20Profile-skarayil-black?style=flat-square&logo=42&logoColor=white)](https://profile.intra.42.fr/users/skarayil)
[![GitHub](https://img.shields.io/badge/GitHub-skarayil-181717?style=flat-square&logo=github&logoColor=white)](https://github.com/skarayil)

**⭐ Eğer bu proje işinize yaradıysa, repo'ya star vermeyi unutmayın!**

</div>

---

**Not:** Bu rehber genel bir yol haritasıdır. 42'nin güncel subject dosyasını mutlaka kontrol edin ve ona göre ilerleyin!
