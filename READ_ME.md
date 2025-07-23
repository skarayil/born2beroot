# Born2beRoot - Kapsamlı Teorik Rehber

📋 İçerik
1. Virtual Machine ve Linux Temelleri
2. LVM ve Disk Yönetimi
3. SSH ve Network Güvenliği
4. Firewall ve UFW
5. User Management ve Permission Sistemi
6. Sudo Sistemi ve Privilege Escalation
7. Password Policy ve PAM
8. Security Modules (AppArmor vs SELinux)
9. System Monitoring Script
10. Security Hardening ve Best Practices
11. Evaluation Hazırlığı
12. Troubleshooting ve Problem Çözme
13. Bonus Part Detayları
14. Proje Teslimi ve Signature


## 🎯 Proje Genel Bakış
Born2beRoot, sistem yönetimi temellerini öğrenmek için tasarlanmış bir projedir. Sanal makine üzerinde Linux server kurulumu yaparak, güvenlik, kullanıcı yönetimi ve sistem izleme konularında deneyim kazanacaksın.

---

## 1. 🖥️ Virtual Machine ve Linux Temelleri

### Virtual Machine Nedir?
Sanal makine (VM), fiziksel bir bilgisayar üzerinde çalışan ve tamamen bağımsız bir bilgisayar sistemi gibi davranabilen yazılım tabanlı bir bilgisayardır.

### Nasıl Çalışır?
```
Fiziksel Bilgisayar (Host)
├── Host İşletim Sistemi (Windows/macOS/Linux)
├── Hypervisor (VirtualBox/VMware)
└── Virtual Machine (Guest OS - Debian)
    ├── Virtual CPU
    ├── Virtual RAM  
    ├── Virtual Disk
    └── Virtual Network Card
```

### VM'nin Avantajları:
- **İzolasyon**: VM crash olsa host sistem etkilenmez
- **Güvenlik**: Virüs bulaşsa sadece VM'i etkiler
- **Test Ortamı**: Farklı sistemleri test edebilirsin
- **Kaynak Paylaşımı**: Bir fiziksel makinde birden fazla OS
- **Portability**: VM dosyasını başka makineye taşıyabilirsin

### VM'nin Dezavantajları:
- **Performance Overhead**: Host sistem kaynaklarını paylaşır
- **Hardware Limitations**: Host'un sınırları içinde kalır
- **Storage**: VM dosyaları büyük yer kaplar
- **Memory Usage**: Host RAM'inin bir kısmını kullanır

### VirtualBox vs UTM
- **VirtualBox**: Intel/AMD işlemciler için ücretsiz, cross-platform
- **UTM**: Apple M1/M2 işlemciler için, ARM tabanlı sistemler
- **Snapshot**: Anlık görüntü alma (projede yasak!)

### Linux ve Dağıtımları

#### İşletim Sistemi Katmanları:
```
Kullanıcı Uygulamaları (Firefox, VS Code)
├── Shell (Bash, Zsh) - Komut satırı arayüzü
├── System Calls - Sistem çağrıları
├── Kernel - İşletim sistemi çekirdeği
└── Hardware - Donanım (CPU, RAM, Disk)
```

#### Linux Dağıtım Aileleri:

**Debian Ailesi:**
```
Debian (Mother distribution)
├── Ubuntu
├── Linux Mint
├── Kali Linux
└── Raspbian
```

**Red Hat Ailesi:**
```
Red Hat Enterprise Linux (RHEL)
├── Fedora
├── CentOS (discontinued)
├── Rocky Linux
└── AlmaLinux
```

### Debian vs Rocky Linux Karşılaştırması:

| Özellik | Debian | Rocky Linux |
|---------|--------|-------------|
| **Base** | Independent | RHEL Clone |
| **Package Manager** | APT (apt/aptitude) | YUM/DNF |
| **Release Model** | Stable/Testing/Unstable | Point Release |
| **Security** | AppArmor | SELinux |
| **Firewall** | UFW | FirewallD |
| **Init System** | systemd | systemd |
| **Learning Curve** | Beginner-friendly | More complex |
| **Enterprise Use** | Moderate | High |

### APT vs Aptitude Farkları:
- **APT**: Command-line paket yöneticisi, hızlı ve basit
- **Aptitude**: İnteraktif interface, dependency resolution daha iyi
- **apt**: Daha user-friendly, renkli output
- **apt-get**: Script'lerde kullanım için stabil interface

### Temel Linux Komutları
```bash
# Sistem bilgisi
uname -a              # Kernel bilgisi
hostnamectl          # Host bilgileri
lsb_release -a       # Dağıtım bilgisi

# Dosya işlemleri
ls -la               # Dosya listesi (detaylı)
pwd                  # Mevcut dizin
cd /path/to/dir      # Dizin değiştir
mkdir directory      # Dizin oluştur
rm -rf directory     # Dizin sil

# Kullanıcı işlemleri
whoami              # Mevcut kullanıcı
id                  # Kullanıcı ID bilgileri
groups              # Grup üyelikleri
su - username       # Kullanıcı değiştir
```

---

## 2. 💾 LVM ve Disk Yönetimi

### Geleneksel Disk Yapısının Problemleri:
```
Physical Disk (/dev/sda)
├── /dev/sda1 (Boot partition) - 500MB
├── /dev/sda2 (Root partition) - 20GB  
└── /dev/sda3 (Swap partition) - 2GB
```

**Sorunlar:**
- Partition boyutları sabit
- Disk dolduğunda resize zor
- Birden fazla disk kullanımı karmaşık
- Flexible değil

### LVM (Logical Volume Manager) Nedir?

LVM, fiziksel diskler üzerinde esnek volume yönetimi sağlayan bir sistem katmanıdır.

```
Physical Volume (PV) - Fiziksel diskler
├── /dev/sda1
└── /dev/sdb1
    │
    ▼
Volume Group (VG) - Disk havuzu
├── VG adı: vg-root
└── Toplam boyut: 40GB
    │
    ▼
Logical Volume (LV) - Mantıksal bölümler  
├── lv-root (/)     - 15GB
├── lv-home (/home) - 20GB
└── lv-var (/var)   - 3GB
```

### LVM Bileşenleri:

#### 1. Physical Volume (PV):
- Fiziksel diskler veya partitions
- LVM'de kullanılmak üzere işaretlenmiş
- `pvcreate /dev/sda1` ile oluşturulur

#### 2. Volume Group (VG): 
- Bir veya birden fazla PV'nin birleşimi
- Disk havuzu gibi düşün
- `vgcreate vg-name /dev/sda1 /dev/sdb1`

#### 3. Logical Volume (LV):
- VG içinden ayrılan mantıksal bölümler
- Mount edilebilir, file system kurulabilir
- `lvcreate -L 10G -n lv-name vg-name`

### LVM Avantajları:
- **Dynamic Resizing**: Partition boyutlarını runtime'da değiştir
- **Multiple Disks**: Birden fazla diski tek volume'da birleştir
- **Snapshots**: Volume'ların anlık görüntülerini al
- **Striping**: Performans için veriyi diskler arası dağıt
- **Mirroring**: Data redundancy için yansıtma

### LVM Komutları
```bash
# PV işlemleri
pvcreate /dev/sda2        # PV oluştur
pvdisplay                 # PV bilgileri
pvs                       # PV özeti

# VG işlemleri
vgcreate vg-name /dev/sda2  # VG oluştur
vgdisplay                   # VG bilgileri
vgs                         # VG özeti
vgextend vg-name /dev/sdb1  # VG'ye disk ekle

# LV işlemleri
lvcreate -L 2G -n lv-swap vg-name    # LV oluştur
lvcreate -l 100%FREE -n lv-root vg-name  # Kalan tüm alanı kullan
lvdisplay                              # LV bilgileri
lvs                                    # LV özeti
lvextend -L +5G /dev/vg-name/lv-root  # LV boyutunu artır
```

### Born2beroot'ta LVM Kullanımı:
```
Encrypted Physical Volume
├── /dev/sda1 (boot) - 500M
└── /dev/sda2 (encrypted LVM) - Remaining space
    │
    ▼ (Encryption layer - LUKS)
    │
    ▼ LVM Volume Group
    ├── root (/) - 10G
    ├── swap - 2G
    ├── home (/home) - 5G
    ├── var (/var) - 3G
    ├── srv (/srv) - 3G
    ├── tmp (/tmp) - 3G
    └── var-log (/var/log) - 4G
```

### Disk Şifreleme (LUKS)

#### LUKS (Linux Unified Key Setup):
- Linux'ta standart disk encryption sistemi
- Block-level encryption sağlar
- Multiple key slots destekler (8 adet)
- Güçlü şifreleme algoritmaları kullanır

#### LUKS Çalışma Prensibi:
```
1. Master Key (Random 256-bit key)
   └── Actual data encryption için kullanılır

2. Key Slots (8 adet slot mevcut)  
   ├── Slot 0: User Password #1
   ├── Slot 1: User Password #2  
   └── Slot 7: Recovery Key
       │
       ▼ (Her slot master key'i şifreler)
```

#### Encryption Process:
```
Raw Data → AES Encryption → Encrypted Data → Disk
    ▲                            │
    └── Master Key ←─────────────┘
            ▲
    User Password (unlocks master key)
```

#### LUKS Komutları:
```bash
# Şifrelenmiş bölüm oluşturma
cryptsetup luksFormat /dev/sda2

# Şifrelenmiş bölümü açma
cryptsetup luksOpen /dev/sda2 encrypted

# Şifrelenmiş bölümü kapatma
cryptsetup luksClose encrypted

# LUKS header bilgileri
cryptsetup luksDump /dev/sda2
```

---

## 3. 🔐 SSH ve Network Güvenliği

### SSH (Secure Shell) Nedir?
SSH, network üzerinden güvenli uzaktan bağlantı kurma protokolüdür.

### SSH'ın Çalışma Prensibi:

#### 1. Connection Establishment:
```
Client                    Server
  │                         │
  ├── TCP Connection ──────▶️ │ (Port 22/4242)
  │                         │
  ├── SSH Version ────────▶️ │
  │◄──── SSH Version ──────┤
```

#### 2. Key Exchange (Diffie-Hellman):
```
  ├── Client Key List ───▶️ │
  │◄── Server Key List ───┤
  │                        │
  ├── Diffie-Hellman ────▶️ │ (Shared secret oluştur)
  │◄── Diffie-Hellman ────┤
```

#### 3. Authentication:
```
  ├── Auth Request ──────▶️ │
  │                        ├── Check: username/password
  │                        │         or public key
  │◄── Auth Response ─────┤
```

#### 4. Encrypted Session:
```
  ├══ Encrypted Data ═══▶️ │
  │◄═ Encrypted Data ════┤
```

### SSH Key Types:

#### 1. Server Keys (Host Keys):
- Server'ın kimliğini doğrular
- `/etc/ssh/ssh_host_*` dosyalarında saklanır
- İlk bağlantıda "host key fingerprint" sorar

#### 2. User Keys (Client Keys):
- Password'sız authentication için
- `~/.ssh/id_rsa` (private key)
- `~/.ssh/id_rsa.pub` (public key)

### SSH Configuration (`/etc/ssh/sshd_config`):

```bash
# Port değiştirme (security through obscurity)
Port 4242

# Root login devre dışı (güvenlik)
PermitRootLogin no

# Password authentication (proje gereği açık)
PasswordAuthentication yes

# Empty password yasak
PermitEmptyPasswords no

# Login attempts limit
MaxAuthTries 3

# Specific users only
AllowUsers sudenaz42

# Protocol version
Protocol 2

# Host key files
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
```

### SSH Security Best Practices:
- **Port değiştir**: Default 22 yerine farklı port
- **Root login yasak**: Normal user kullan, sudo ile yetki al
- **Strong passwords**: Karmaşık şifreler
- **Key-based auth**: Mümkünse public key kullan
- **Fail2ban**: Brute force saldırıları engelle
- **Firewall**: Sadece gerekli portları aç

### SSH Key Authentication:
```bash
# Key çifti oluşturma
ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa

# Public key'i sunucuya kopyalama
ssh-copy-id -p 4242 username@server

# Manual copy (alternatif)
cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys

# SSH bağlantısı
ssh -p 4242 username@server
```

### Network Temelleri
- **IP Address**: Ağdaki benzersiz adres (192.168.1.100)
- **MAC Address**: Fiziksel ağ kartının adresi (08:00:27:51:9b:a5)
- **Port**: Uygulamaların ağ üzerindeki kapıları (4242, 80, 443)
- **TCP vs UDP**: Güvenilir vs hızlı iletişim

---

## 4. 🔥 Firewall ve UFW (Uncomplicated Firewall)

### Firewall Nedir?
Firewall, network trafiğini kontrol eden güvenlik sistemidir. Gelen ve giden veri paketlerini kurallara göre kabul eder veya reddeder.

### Linux Firewall Stack:
```
User Space Applications
├── UFW (User-friendly frontend)
├── firewalld (Enterprise frontend)  
└── iptables (Advanced management)
    │
    ▼
Kernel Space
└── Netfilter (Core firewall framework)
    ├── Tables: filter, nat, mangle
    ├── Chains: INPUT, OUTPUT, FORWARD
    └── Rules: ACCEPT, DROP, REJECT
```

### UFW (Uncomplicated Firewall):

UFW, iptables'ın kullanıcı dostu bir frontend'idir.

#### UFW Basic Commands:
```bash
# UFW'yi aktif et
sudo ufw enable

# Status kontrol
sudo ufw status verbose

# Default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Port işlemleri
sudo ufw allow 4242/tcp
sudo ufw allow ssh
sudo ufw deny 80/tcp

# Specific IP'den connection
sudo ufw allow from 192.168.1.100

# Port range
sudo ufw allow 1000:2000/tcp

# Rule silme
sudo ufw delete allow 4242/tcp

# Reset all rules
sudo ufw --force reset

# Rule numaraları ile
sudo ufw status numbered
sudo ufw delete 2
```

### Firewalld (Rocky Linux):
```bash
# Firewalld etkinleştirme
systemctl enable firewalld
systemctl start firewalld

# Zone yönetimi
firewall-cmd --get-active-zones
firewall-cmd --get-default-zone
firewall-cmd --set-default-zone=public

# Port yönetimi
firewall-cmd --permanent --add-port=4242/tcp
firewall-cmd --reload

# Service yönetimi
firewall-cmd --permanent --add-service=ssh
firewall-cmd --remove-service=dhcpv6-client

# Status kontrolü
firewall-cmd --list-all
```

### Born2beroot Firewall Configuration:
```bash
# Default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# SSH port açma  
sudo ufw allow 4242/tcp

# Firewall'ı aktif et
sudo ufw enable

# Status kontrolü
sudo ufw status numbered
```

### Firewall Security Principles:
- **Default Deny**: Varsayılan olarak her şeyi reddet
- **Least Privilege**: Sadece gerekli portları aç
- **Regular Review**: Kuralları düzenli gözden geçir
- **Logging**: Suspicious activity'leri logla
- **Testing**: Rule değişikliklerini test et

---

## 5. 👥 User Management ve Permission Sistemi

### Linux User System Architecture:
```
Users
├── Root (UID 0) - Super user
├── System Users (UID 1-999) - Services
└── Regular Users (UID 1000+) - Human users

Groups  
├── Primary Group - User'ın default grubu
└── Secondary Groups - Ek grup üyelikleri
```

### User Information Files:

#### /etc/passwd:
```
username:password:UID:GID:GECOS:home_dir:shell
sudenaz42:x:1000:1000:Sude Naz,,,:/home/sudenaz42:/bin/bash

Fields:
- username: Kullanıcı adı
- password: 'x' (şifre /etc/shadow'da)
- UID: User ID
- GID: Primary Group ID
- GECOS: Full name, room, phone, etc.
- home_dir: Home directory path
- shell: Default shell
```

#### /etc/shadow:
```
username:encrypted_password:last_changed:min:max:warn:inactive:expire
sudenaz42:$6$rounds=656000$...:19000:2:30:7:::

Fields:
- username: Kullanıcı adı
- encrypted_password: Şifrelenmiş şifre
- last_changed: Son değişiklik tarihi (1970'den itibaren gün)
- min: Min değişiklik aralığı (gün)
- max: Max geçerlilik süresi (gün)
- warn: Uyarı süresi (gün)
- inactive: Inactive period
- expire: Account expiry date
```

#### /etc/group:
```
group_name:password:GID:user_list
sudo:x:27:sudenaz42
user42:x:1001:sudenaz42

Fields:
- group_name: Grup adı
- password: Grup şifresi (genelde kullanılmaz)
- GID: Group ID
- user_list: Grup üyeleri (virgülle ayrılmış)
```

### User Management Commands:

#### User Operations:
```bash
# User oluşturma
sudo adduser newuser                    # Interactive user creation
sudo useradd -m -s /bin/bash newuser   # Manual user creation

# User silme  
sudo deluser newuser                    # Remove user
sudo deluser --remove-home newuser     # Remove user and home dir

# User info değiştirme
sudo usermod -aG sudo newuser          # Gruba ekleme
sudo usermod -l newname oldname        # İsim değiştirme
sudo usermod -d /new/home -m username  # Home dir değiştirme
sudo usermod -s /bin/zsh username      # Shell değiştirme

# User info görme
id username             # User ID info
groups username         # Group memberships
finger username         # Detailed user info
getent passwd username  # Passwd entry
```

#### Group Operations:
```bash
# Grup oluşturma
sudo groupadd user42

# User'ı gruba ekleme  
sudo usermod -aG user42 sudenaz42
sudo gpasswd -a sudenaz42 user42

# User'ı gruptan çıkarma
sudo deluser sudenaz42 user42
sudo gpasswd -d sudenaz42 user42

# Grup silme
sudo groupdel user42

# Grup listesi
groups
cat /etc/group
getent group
```

### Linux Permission System:

#### File Permissions:
```
-rwxrwxrwx
│││││││││└── Other execute
││││││││└─── Other write  
│││││││└──── Other read
││││││└───── Group execute
│││││└────── Group write
││││└─────── Group read  
│││└──────── Owner execute
││└───────── Owner write
│└────────── Owner read
└─────────── File type (- = file, d = directory, l = symlink)
```

#### Numeric Permissions:
```
Read (r) = 4
Write (w) = 2  
Execute (x) = 1

Examples:
755 = rwxr-xr-x (Owner: rwx, Group: r-x, Other: r-x)
644 = rw-r--r-- (Owner: rw-, Group: r--, Other: r--)
600 = rw------- (Owner: rw-, Group: ---, Other: ---)
700 = rwx------ (Owner: rwx, Group: ---, Other: ---)
```

#### Permission Commands:
```bash
# Permission değiştirme
chmod 755 file.txt              # Numeric mode
chmod u+x file.txt              # User execute ekle
chmod g-w file.txt              # Group write kaldır
chmod o=r file.txt              # Other sadece read

# Owner değiştirme
chown user:group file.txt       # User ve group değiştir
chown user file.txt             # Sadece user değiştir
chgrp group file.txt            # Sadece group değiştir

# Recursive işlemler
chmod -R 755 directory/
chown -R user:group directory/
```

#### Special Permissions:
```bash
# Sticky Bit (1000) - Sadece owner silebilir
chmod 1755 /tmp

# SGID (2000) - Group inheritance
chmod 2755 directory

# SUID (4000) - Run as owner
chmod 4755 /usr/bin/passwd
```

---

## 6. 🔐 Sudo Sistemi ve Privilege Escalation

### Sudo Nedir?
Sudo (Super User Do), normal kullanıcıların geçici olarak root yetkilerini kullanmasını sağlayan sistemdir.

### Sudo vs Su Farkı:

#### Su (Switch User):
- Tamamen farklı user'a geçer
- Root şifresini bilmen gerekir
- Session tamamen root olur
- `su -` komutu ile kullanılır

#### Sudo (Super User Do):
- Sadece komut bazında yetki verir
- Kendi şifreni kullanırsın  
- Geçici yetki, komut bitince normal user
- Granular permission control

### Sudo Configuration (/etc/sudoers):

#### Basic Syntax:
```
user    host=(runas)    commands
%group  host=(runas)    commands

Examples:
sudenaz42    ALL=(ALL:ALL) ALL              # Full sudo access
%sudo        ALL=(ALL:ALL) ALL              # Sudo group members
john         ALL=(root) /bin/systemctl      # Only systemctl as root
mary         ALL=(ALL) NOPASSWD: /bin/ls    # No password for ls
```

#### sudoers File Structure:
```bash
# Host aliases
Host_Alias  SERVERS = 192.168.1.0/24, server1, server2

# User aliases  
User_Alias  ADMINS = john, mary, sudenaz42

# Command aliases
Cmnd_Alias  SERVICES = /bin/systemctl, /usr/sbin/service
Cmnd_Alias  NETWORKING = /sbin/ifconfig, /bin/netstat

# Defaults
Defaults    passwd_tries=3
Defaults    badpass_message="Wrong password!"
Defaults    logfile="/var/log/sudo/sudo.log"
Defaults    requiretty
Defaults    secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# User specifications
root        ALL=(ALL:ALL) ALL
%admin      ALL=(ALL) ALL
%sudo       ALL=(ALL:ALL) ALL
ADMINS      SERVERS=(ALL) SERVICES
```

### Born2beroot Sudo Requirements:

#### 1. Password Attempts (3 tries):
```
Defaults    passwd_tries=3
```

#### 2. Custom Error Message:
```  
Defaults    badpass_message="Access denied! Please check your credentials."
```

#### 3. Logging (Input/Output):
```
Defaults    log_input,log_output
Defaults    logfile="/var/log/sudo/sudo.log"
Defaults    iolog_dir="/var/log/sudo"
```

#### 4. TTY Requirement:
```
Defaults    requiretty
```

#### 5. Secure Path:
```
Defaults    secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
```

### Sudo Configuration File:
```bash
# /etc/sudoers.d/sudo_config dosyası oluştur
echo "Defaults passwd_tries=3" >> /etc/sudoers.d/sudo_config
echo "Defaults badpass_message=\"Wrong password, try again!\"" >> /etc/sudoers.d/sudo_config
echo "Defaults logfile=\"/var/log/sudo/sudo.log\"" >> /etc/sudoers.d/sudo_config
echo "Defaults log_input,log_output" >> /etc/sudoers.d/sudo_config
echo "Defaults iolog_dir=\"/var/log/sudo\"" >> /etc/sudoers.d/sudo_config
echo "Defaults requiretty" >> /etc/sudoers.d/sudo_config
echo "Defaults secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin\"" >> /etc/sudoers.d/sudo_config
```

### Sudo Security Features:

#### Timestamp Timeout:
- sudo kullandıktan sonra 15 dakika boyunca şifre sorulmaz
- `sudo -k` ile timestamp sıfırlanır
- `sudo -v` ile timestamp yenilenir

#### Environment Cleaning:
- Güvenlik için environment variables temizlenir
- PATH, HOME gibi değişkenler kontrol edilir

#### Command Logging:
- Tüm sudo komutları loglanır
- `/var/log/auth.log` veya custom log file
- Input/output logging mümkün

### Sudo Commands:
```bash
# Sudo permissions kontrol
sudo -l                    # Hangi komutları çalıştırabilirim?

# Farklı user olarak çalıştır
sudo -u username command   # Specific user olarak

# Root shell aç
sudo -i                    # Login shell
sudo -s                    # Current shell

# Environment preserve
sudo -E command            # Environment variables koru

# Timestamp operations
sudo -v                    # Timestamp yenile
sudo -k                    # Timestamp sıfırla
```

---

## 7. 🔑 Password Policy ve PAM (Pluggable Authentication Modules)

### Password Security Nedir?
Password güvenliği, sistemdeki en zayıf halka olan şifreleri güçlendirme sürecidir.

### Common Password Attacks:
1. **Dictionary Attack**: Yaygın şifre listeleri dener
2. **Brute Force**: Tüm kombinasyonları dener
3. **Rainbow Tables**: Pre-computed hash tables
4. **Social Engineering**: İnsani faktör istismarı
5. **Credential Stuffing**: Sızan şifreler denenilir

### Linux Password System:

#### Password Storage:
```
/etc/passwd  → User bilgileri (şifre yok!)
/etc/shadow  → Encrypted passwords
/etc/group   → Group bilgileri
```

#### /etc/shadow Format:
```
username:$id$salt$hashed:lastchg:min:max:warn:inactive:expire:flag

$id$ → Hashing algorithm
├── $1$ = MD5 (deprecated)
├── $2a$ = Blowfish  
├── $5$ = SHA-256  
├── $6$ = SHA-512 (recommended)
└── $y$ = yescrypt
```

### PAM (Pluggable Authentication Modules):

PAM, Linux'ta authentication, authorization ve session management sağlayan modüler sistemdir.

#### PAM Architecture:
```
Application (login, ssh, sudo)
         │
         ▼
    PAM Library
         │
         ▼
PAM Configuration Files (/etc/pam.d/)
         │
         ▼
PAM Modules (shared libraries)
├── pam_unix.so     - Standard Unix auth
├── pam_cracklib.so - Password strength
├── pam_pwquality.so - Password quality
├── pam_limits.so   - Resource limits
└── pam_faildelay.so - Login delay
```

#### PAM Module Types:
1. **auth**: Authentication (kimlik doğrulama)
2. **account**: Account validation (hesap kontrolü)
3. **password**: Password management (şifre yönetimi)
4. **session**: Session setup (oturum kurulum)

#### PAM Control Types:
- **required**: Must succeed, continue processing
- **requisite**: Must succeed, stop if fails  
- **sufficient**: Success stops processing
- **optional**: Success/failure doesn't matter
- **include**: Include another config file
- **substack**: Like include but isolated

### Password Policy Configuration:

#### /etc/login.defs:
```bash
# Password aging controls
PASS_MAX_DAYS   30    # Expire after 30 days
PASS_MIN_DAYS   2     # Min 2 days before change
PASS_WARN_AGE   7     # Warn 7 days before expire

# User creation defaults
UID_MIN         1000  # Minimum UID for regular users
UID_MAX         60000 # Maximum UID for regular users
GID_MIN         1000  # Minimum GID for regular groups
GID_MAX         60000 # Maximum GID for regular groups
CREATE_HOME     yes   # Create home directory
UMASK           022   # Default file permissions
USERGROUPS_ENAB yes   # Create group with same name as user

# Password encryption method
ENCRYPT_METHOD  SHA512

# Login timeout

LOGIN_TIMEOUT   60    # Login timeout (seconds)

# Failed login attempts  
LOGIN_RETRIES   3     # Max failed login attempts
FAIL_DELAY      5     # Delay after failed login

# Home directory permissions
HOME_MODE       0750  # Home directory permissions

# Shell timeout
TMOUT           600   # Shell timeout (10 minutes)
PAM Password Quality (pwquality): /etc/security/pwquality.conf:


bash
# Password length
minlen = 10              # Minimum 10 characters

# Character classes (at least one from each)
dcredit = -1             # At least 1 digit
ucredit = -1             # At least 1 uppercase  
lcredit = -1             # At least 1 lowercase
ocredit = -1             # At least 1 special char

# Repetition rules
maxrepeat = 3            # Max 3 consecutive identical chars
maxclasschars = 0        # Max chars from same class (0=unlimited)

# Dictionary checks
dictcheck = 1            # Enable dictionary checking
usercheck = 1            # Check against username
enforcing = 1            # Enforce policy

# Similarity checks  
difok = 7                # Min 7 different chars from old password
minclass = 0             # Min character classes required

# Custom reject patterns
reject_username          # Reject if contains username
gecoscheck = 1           # Check against GECOS fields
Born2beroot Password Policy Implementation:


bash
# 1. /etc/login.defs düzenleme
sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t30/' /etc/login.defs
sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t2/' /etc/login.defs  
sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE\t7/' /etc/login.defs

# 2. pwquality configuration
echo "minlen = 10" >> /etc/security/pwquality.conf
echo "dcredit = -1" >> /etc/security/pwquality.conf
echo "ucredit = -1" >> /etc/security/pwquality.conf
echo "lcredit = -1" >> /etc/security/pwquality.conf
echo "maxrepeat = 3" >> /etc/security/pwquality.conf
echo "reject_username" >> /etc/security/pwquality.conf
echo "difok = 7" >> /etc/security/pwquality.conf
echo "enforce_for_root" >> /etc/security/pwquality.conf

# 3. Mevcut kullanıcılar için password aging
sudo chage -M 30 sudenaz42    # Max days
sudo chage -m 2 sudenaz42     # Min days  
sudo chage -W 7 sudenaz42     # Warning days

# 4. Root için de aynı kurallar
sudo chage -M 30 root
sudo chage -m 2 root
sudo chage -W 7 root
Password Commands:


bash
# Password change
passwd                    # Own password
sudo passwd username      # Other user's password

# Password aging info
chage -l username         # View aging info
sudo chage username       # Interactive aging setup

# Specific aging settings
chage -M 30 username      # Max days
chage -m 2 username       # Min days
chage -W 7 username       # Warning days
chage -I 10 username      # Inactive days
chage -E 2024-12-31 username  # Expiry date

# Force password change on next login
chage -d 0 username

# Lock/unlock account
passwd -l username        # Lock account
passwd -u username        # Unlock account
passwd -S username        # Show status
Password Hash Analysis:


bash
# /etc/shadow örneği
sudenaz42:$6$rounds=656000$YourSalt$HashValue:19000:2:30:7:::

Breakdown:
- $6$ = SHA-512 hashing
- rounds=656000 = Hash iterations (güvenlik için)
- YourSalt = Random salt value
- HashValue = Actual password hash
- 19000 = Days since Jan 1, 1970 (last change)
- 2 = Min days before change allowed
- 30 = Max days password valid
- 7 = Warning days before expiry
8. 🔒 Security Modules (AppArmor vs SELinux)
AppArmor (Application Armor)
AppArmor, uygulamaları kısıtlayarak sistem güvenliğini artıran Mandatory Access Control (MAC) sistemidir.
AppArmor Çalışma Prensibi:


Traditional Linux Security (DAC)
├── User permissions (rwx)
├── Group permissions (rwx) 
└── Other permissions (rwx)

AppArmor (MAC) - Additional Layer
├── Path-based access control
├── Network access control
├── Capability restrictions
└── Resource limitations
AppArmor Profile Modes:
1. Enforce Mode: Profil aktif, ihlaller engellenr
2. Complain Mode: Profil pasif, sadece loglar
3. Unconfined: Profil yok, normal DAC
AppArmor Profile Structure:


bash
#include <tunables/global>

/usr/sbin/nginx {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  capability dac_override,
  capability setuid,
  capability setgid,

  /usr/sbin/nginx mr,
  /etc/nginx/ r,
  /etc/nginx/** r,
  /var/log/nginx/ w,
  /var/log/nginx/** w,
  /var/www/** r,

  deny /etc/shadow r,
  deny /home/** r,
}
AppArmor Commands:


bash
# Status kontrolü
sudo apparmor_status

# Profile load/reload
sudo apparmor_parser -r /etc/apparmor.d/usr.sbin.nginx

# Profile modes  
sudo aa-enforce /etc/apparmor.d/usr.sbin.nginx    # Enforce mode
sudo aa-complain /etc/apparmor.d/usr.sbin.nginx   # Complain mode
sudo aa-disable /etc/apparmor.d/usr.sbin.nginx    # Disable profile

# Log monitoring
sudo aa-logprof     # Interactive profile generator
tail -f /var/log/kern.log | grep -i apparmor
SELinux (Security-Enhanced Linux)
SELinux, NSA tarafından geliştirilen, çok güçlü MAC sistemidir.
SELinux vs AppArmor:
Özellik	AppArmor	SELinux
Approach	Path-based	Label-based
Complexity	Simple	Complex
Performance	Lower overhead	Higher overhead
Flexibility	Limited	Very flexible
Learning Curve	Easy	Steep
Default in	Debian/Ubuntu	RHEL/Rocky
SELinux Contexts:


bash
# SELinux context format
user:role:type:level

Examples:
system_u:system_r:httpd_t:s0        # Apache process
system_u:object_r:httpd_config_t:s0 # Apache config files
unconfined_u:unconfined_r:unconfined_t:s0  # Normal user process
SELinux Modes:
1. Enforcing: SELinux aktif, ihlaller engellenr
2. Permissive: SELinux pasif, sadece loglar
3. Disabled: SELinux kapalı
SELinux Commands:


bash
# Status kontrolü
sestatus
getenforce

# Mode değiştirme  
sudo setenforce 1      # Enforcing
sudo setenforce 0      # Permissive

# Context görme
ls -Z /etc/passwd      # File context
ps -Z                  # Process context
id -Z                  # User context

# Policy management
getsebool -a           # List all booleans
setsebool httpd_can_network_connect on  # Set boolean

# Log analizi
sealert -a /var/log/audit/audit.log
Born2beroot Security Module Setup:
Debian (AppArmor):


bash
# AppArmor kurulum kontrolü
sudo apt update
sudo apt install apparmor apparmor-utils

# Systemd service aktif et
sudo systemctl enable apparmor
sudo systemctl start apparmor

# Status kontrolü
sudo apparmor_status
Rocky Linux (SELinux):


bash
# SELinux durumu kontrol
sestatus

# /etc/selinux/config düzenleme
SELINUX=enforcing
SELINUXTYPE=targeted

# Reboot sonrası aktif olur
sudo reboot
9. 📊 System Monitoring Script
Monitoring Script Gereksinimleri
Born2beroot projesinde her 10 dakikada bir sistem bilgilerini gösteren monitoring.sh scripti gerekiyor.
Script'in göstermesi gereken bilgiler:
1. İşletim sistemi mimarisi ve kernel versiyonu
2. Fiziksel işlemci sayısı
3. Sanal işlemci sayısı
4. RAM kullanımı (mevcut/toplam ve yüzde)
5. Disk kullanımı (mevcut/toplam ve yüzde)
6. CPU yük yüzdesi
7. Son reboot tarihi ve saati
8. LVM aktif mi?
9. Aktif TCP bağlantı sayısı
10. Aktif kullanıcı sayısı
11. IPv4 adresi ve MAC adresi
12. Sudo ile çalıştırılan komut sayısı
Linux System Information Commands
Architecture ve Kernel:


bash
uname -a    # Tüm sistem bilgileri
uname -m    # Machine architecture (x86_64)
uname -r    # Kernel release (5.10.0-18-amd64)
uname -s    # Kernel name (Linux)
CPU Information:


bash
# Fiziksel CPU sayısı
grep "physical id" /proc/cpuinfo | sort -u | wc -l

# Sanal CPU (core) sayısı  
grep -c ^processor /proc/cpuinfo

# Alternatif yöntem
lscpu | grep "CPU(s):"
nproc    # Logical CPU count
Memory Information:


bash
# RAM bilgileri
free -m              # MB cinsinden
free -h              # Human readable
cat /proc/meminfo    # Detaylı bilgi

# Memory usage calculation
used_ram=$(free -m | awk 'NR==2{printf "%.0f", $3}')
total_ram=$(free -m | awk 'NR==2{printf "%.0f", $2}')
ram_percent=$(free | awk 'NR==2{printf "%.2f", $3/$2*100.0}')
Disk Information:


bash
# Disk usage
df -h               # Human readable  
df -BG             # Gigabyte cinsinden
du -sh /           # Root directory size

# Disk usage calculation
disk_used=$(df -BG | grep '^/dev/' | awk '{used += $3} END {print used}')
disk_total=$(df -BG | grep '^/dev/' | awk '{total += $2} END {print total}')
disk_percent=$(df | grep '^/dev/' | awk '{used += $3; total += $2} END {printf "%.0f", used/total*100}')
CPU Load:


bash
# CPU usage
top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1

# Load average
uptime | awk -F'load average:' '{ print $2 }' | cut -d, -f1

# vmstat ile
vmstat 1 2 | tail -1 | awk '{printf "%.1f%%", 100-$15}'
System Uptime/Reboot:


bash
# Last boot time
who -b | awk '{print $3, $4}'
uptime -s          # System start time
last reboot | head -1    # Last reboot info
LVM Status:


bash
# LVM aktif mi?
if [ $(lsblk | grep "lvm" | wc -l) -eq 0 ]; then
    echo "no"
else  
    echo "yes"
fi
Network Connections:


bash
# Active TCP connections
ss -ta | grep ESTAB | wc -l
netstat -tn | grep ESTABLISHED | wc -l

# Alternatif
cat /proc/net/tcp | wc -l
Active Users:


bash
# Logged in users
who | wc -l
users | wc -w
w | grep -v ^USER | wc -l
Network Interface:


bash
# IP address
hostname -I | awk '{print $1}'
ip route get 1.1.1.1 | grep -oP 'src \K\S+'

# MAC address  
ip link show | grep "link/ether" | awk '{print $2}'
cat /sys/class/net/$(ip route show default | awk '/default/ {print $5}')/address
Sudo Commands Count:


bash
# /var/log/sudo/sudo.log dosyasındaki komut sayısı
grep -c "COMMAND" /var/log/sudo/sudo.log

# Alternatif auth.log'dan
grep -c "sudo.*COMMAND" /var/log/auth.log
Complete Monitoring Script

#!/bin/bash

# Born2beroot System Monitoring Script
# Bu script her 10 dakikada bir sistem bilgilerini gösterir

# Renk kodları (isteğe bağlı)
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Banner (isteğe bağlı)
echo -e "${BLUE}"
echo "╔══════════════════════════════════════╗"
echo "║        SYSTEM MONITORING INFO        ║"
echo "╚══════════════════════════════════════╝"
echo -e "${NC}"

# 1. Architecture ve Kernel versiyonu
arch=$(uname -a)
echo -e "${GREEN}#Architecture:${NC} $arch"

# 2. Fiziksel CPU sayısı
pcpu=$(grep "physical id" /proc/cpuinfo | sort -u | wc -l)
echo -e "${GREEN}#CPU physical:${NC} $pcpu"

# 3. Sanal CPU sayısı  
vcpu=$(grep -c ^processor /proc/cpuinfo)
echo -e "${GREEN}#vCPU:${NC} $vcpu"

# 4. RAM kullanımı
memory_usage=$(free -m | awk 'NR==2{printf "%s/%sMB (%.2f%%)", $3,$2,$3*100/$2}')
echo -e "${GREEN}#Memory Usage:${NC} $memory_usage"

# 5. Disk kullanımı
disk_usage=$(df -BG | grep '^/dev/' | awk '{used += $3; total += $2} END {printf "%dG/%dG (%d%%)", used, total, used/total*100}')
echo -e "${GREEN}#Disk Usage:${NC} $disk_usage"

# 6. CPU yük yüzdesi
cpu_load=$(vmstat 1 2 | tail -1 | awk '{printf "%.1f%%", 100-$15}')
echo -e "${GREEN}#CPU load:${NC} $cpu_load"

# 7. Son reboot tarihi
last_boot=$(who -b | awk '{print $3, $4}')
echo -e "${GREEN}#Last boot:${NC} $last_boot"

# 8. LVM kullanımı
if [ $(lsblk | grep "lvm" | wc -l) -eq 0 ]; then
    lvm_use="no"
else
    lvm_use="yes"
fi
echo -e "${GREEN}#LVM use:${NC} $lvm_use"

# 9. TCP bağlantıları
tcp_conn=$(ss -ta | grep ESTAB | wc -l)
echo -e "${GREEN}#Connections TCP:${NC} $tcp_conn ESTABLISHED"

# 10. Aktif kullanıcı sayısı
user_log=$(who | wc -l)
echo -e "${GREEN}#User log:${NC} $user_log"

# 11. Network bilgileri
ip_addr=$(hostname -I | awk '{print $1}')
mac_addr=$(ip link show | grep "link/ether" | awk '{print $2}' | head -n1)
echo -e "${GREEN}#Network:${NC} IP $ip_addr ($mac_addr)"

# 12. Sudo komut sayısı
if [ -f "/var/log/sudo/sudo.log" ]; then
    sudo_cmd=$(grep -c "COMMAND" /var/log/sudo/sudo.log 2>/dev/null || echo "0")
else
    sudo_cmd=$(grep -c "sudo.*COMMAND" /var/log/auth.log 2>/dev/null || echo "0")
fi
echo -e "${GREEN}#Sudo:${NC} $sudo_cmd cmd"

# Alt çizgi (isteğe bağlı)
echo -e "${BLUE}════════════════════════════════════════${NC}"

Cron Job Configuration
Cron Nedir? Cron, Linux sistemlerde zamanlanmış görevleri çalıştıran daemon (background service)'dir.
Crontab Syntax:


* * * * * command
│ │ │ │ │
│ │ │ │ └── Day of week (0-7, 0 ve 7 = Pazar)
│ │ │ └──── Month (1-12)
│ │ └────── Day of month (1-31)  
│ └──────── Hour (0-23)
└────────── Minute (0-59)

Examples:
0 */10 * * * → Her 10 dakikada bir (0, 10, 20, 30, 40, 50)
*/10 * * * * → Her 10 dakikada bir  
0 0 * * * → Her gün gece yarısı
0 0 * * 0 → Her Pazar gece yarısı
*/5 9-17 * * 1-5 → Hafta içi, 9-17 arası her 5 dakika
Born2beroot Cron Setup:


bash
# 1. Script'i oluştur ve yetki ver
sudo nano /root/monitoring.sh
sudo chmod +x /root/monitoring.sh

# 2. Crontab düzenle  
sudo crontab -e

# 3. Bu satırı ekle (her 10 dakikada bir, wall ile tüm terminallere gönder)
*/10 * * * * /root/monitoring.sh | wall

# 4. Cron servisini kontrol et
sudo systemctl status cron
sudo systemctl enable cron
sudo systemctl start cron
Cron Commands:


bash
# Crontab görüntüle
crontab -l          # Current user
sudo crontab -l     # Root user

# Crontab düzenle  
crontab -e          # Current user
sudo crontab -e     # Root user

# Crontab sil
crontab -r          # Remove all jobs

# Cron log'ları
tail -f /var/log/cron.log
grep CRON /var/log/syslog
Wall Command
Wall (Write All), tüm aktif terminal oturumlarına mesaj gönderen komuttur.


bash
# Basit mesaj gönderme
echo "Server maintenance in 10 minutes!" | wall

# Script çıktısını wall ile gönderme  
/root/monitoring.sh | wall

# Interactive wall
wall
Type your message here...
Press Ctrl+D to send
Wall Örnek Çıktı:


Broadcast message from root@sudenaz42 (pts/0) (Tue Oct 24 15:30:01 2023):

╔══════════════════════════════════════╗
║        SYSTEM MONITORING INFO        ║
╚══════════════════════════════════════╝

#Architecture: Linux sudenaz42 5.10.0-18-amd64 #1 SMP Debian 5.10.140-1 (2022-09-02) x86_64 GNU/Linux
#CPU physical: 1
#vCPU: 1
#Memory Usage: 156/987MB (15.81%)
#Disk Usage: 2G/8G (25%)
#CPU load: 12.5%
#Last boot: 2023-10-24 14:30
#LVM use: yes
#Connections TCP: 3 ESTABLISHED
#User log: 2
#Network: IP 10.0.2.15 (08:00:27:51:9b:a5)
#Sudo: 45 cmd
10. 🛡️ Security Hardening ve Best Practices
System Hardening Checklist
1. User Account Security:


bash
# Gereksiz user'ları sil veya kilitle
sudo usermod -L daemon
sudo usermod -L bin
sudo usermod -L sys

# Root login'i sadece console'dan izin ver
sudo sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config

# Empty password'leri yasakla
sudo sed -i 's/^#PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
2. Network Security:


bash
# Gereksiz servisleri kapat
sudo systemctl disable bluetooth
sudo systemctl disable avahi-daemon  
sudo systemctl disable cups

# Network parameters (sysctl)
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
3. File System Security:


bash
# Sensitive file permissions
sudo chmod 600 /etc/shadow
sudo chmod 600 /etc/gshadow  
sudo chmod 644 /etc/passwd
sudo chmod 644 /etc/group

# Remove world-writable files
find / -type f -perm -002 -exec chmod 644 {} \; 2>/dev/null

# Set sticky bit on /tmp
sudo chmod +t /tmp
4. Logging ve Auditing:


bash
# Rsyslog yapılandırması
echo "*.* /var/log/all.log" >> /etc/rsyslog.conf

# Log rotation
sudo nano /etc/logrotate.d/custom
Defense in Depth Strategy
Security Layers:


┌─────────────────────────────────────┐
│          Physical Security          │
├─────────────────────────────────────┤
│            Network Firewall         │  
├─────────────────────────────────────┤
│          Host-based Firewall        │
├─────────────────────────────────────┤
│         Access Control (MAC)        │
├─────────────────────────────────────┤
│      Application Security (PAM)     │
├─────────────────────────────────────┤
│         User Authentication         │
├─────────────────────────────────────┤
│           Data Encryption           │
└─────────────────────────────────────┘
Born2beroot Security Implementation:
1. Encryption: LUKS disk encryption
2. Access Control: Strong password policy + sudo restrictions
3. Network Security: UFW firewall + non-standard SSH port
4. System Integrity: AppArmor/SELinux mandatory access control
5. Monitoring: System monitoring script + logging
6. User Management: Least privilege principle
Incident Response
Log Files to Monitor:


bash
/var/log/auth.log        # Authentication attempts
/var/log/syslog         # System messages  
/var/log/kern.log       # Kernel messages
/var/log/sudo/sudo.log  # Sudo command logs
/var/log/ufw.log        # Firewall logs
/var/log/cron.log       # Cron job logs
Security Monitoring Commands:


bash
# Failed login attempts
sudo grep "Failed password" /var/log/auth.log

# Successful logins
sudo grep "Accepted password" /var/log/auth.log

# Sudo usage
sudo grep "COMMAND" /var/log/sudo/sudo.log

# Firewall blocks
sudo grep "BLOCK" /var/log/ufw.log

# System changes
sudo find /etc -type f -newer /var/log/dpkg.log
11. 📋 Değerlendirme Kriterleri ve Defense Hazırlığı
Defense Questions & Answers
1. Virtual Machine Questions:
* Q: Virtual Machine nedir ve nasıl çalışır?
* A: VM, fiziksel hardware üzerinde çalışan sanal bilgisayardır. Hypervisor sayesinde kaynakları paylaşarak izole ortamlar sağlar.
2. Operating System Questions:
* Q: Debian ve Rocky Linux arasındaki farklar nelerdir?
* A: Debian community-driven, APT kullanır, AppArmor security; Rocky ise RHEL clone, YUM/DNF kullanır, SELinux security.
* Q: APT ve Aptitude arasındaki fark nedir?
* A: APT command-line tool, hızlı; Aptitude interactive interface, daha iyi dependency resolution.
3. User Management Questions:
* Q: Sudo nedir ve neden kullanılır?
* A: Sudo, normal kullanıcılara geçici root yetkileri verir. Security için root direkt kullanımından daha güvenli.
* Q: User42 grubunu neden oluşturduk?
* A: Proje gereksinimi, specific group permissions için.
4. Security Questions:
* Q: UFW nedir ve neden port 4242 seçtik?
* A: UFW (Uncomplicated Firewall) iptables frontend'i. 4242 non-standard port, security through obscurity için.
* Q: AppArmor/SELinux ne işe yarar?
* A: Mandatory Access Control (MAC) sistemi, uygulamaları kısıtlayarak ek güvenlik katmanı sağlar.
5. LVM Questions:
* Q: LVM nedir ve avantajları nelerdir?
* A: Logical Volume Manager, flexible disk management sağlar. Runtime resize, multiple disk birleştirme gibi avantajları var.
6. Password Policy Questions:
* Q: Password policy neden önemli?
* A: Weak password'ler sistemin en zayıf halkası. Strong policy brute force ve dictionary attack'leri zorlaştırır.
7. Monitoring Script Questions:
* Q: Monitoring script nasıl çalışır?
* A: Cron job her 10 dakikada scripti çalıştırır, wall komutu ile tüm terminallere system info gönderir.
* Q: Cron nedir?
* A: Time-based job scheduler, zamanlanmış görevleri otomatik çalıştırır.
Evaluation Simulation Commands
Defense sırasında gösterilmesi gereken komutlar:


bash
# 1. System information
uname -a
hostnamectl
lsb_release -a

# 2. User management
sudo adduser newuser
sudo usermod -aG user42 newuser
sudo usermod -aG sudo newuser
groups newuser

# 3. Password policy test  
sudo chage -l newuser
passwd newuser  # Strong password test

# 4. Sudo configuration
sudo visudo -f /etc/sudoers.d/sudo_config
sudo -l

# 5. UFW firewall
sudo ufw status numbered
sudo ufw allow 8080
sudo ufw delete allow 8080

# 6. SSH configuration
sudo systemctl status ssh
ssh newuser@localhost -p 4242

# 7. LVM information
lsblk
sudo vgs
sudo lvs  
sudo pvs

# 8. Monitoring script
sudo /root/monitoring.sh
sudo crontab -l

# 9. Security modules
sudo apparmor_status  # Debian
sestatus              # Rocky

# 10. Log files
sudo tail /var/log/sudo/sudo.log
sudo tail /var/log/auth.log
Performance Optimization
VM Resource Allocation:


Minimum Requirements:
├── RAM: 1024 MB (1GB)
├── Storage: 8 GB
├── CPU: 1 core
└── Network: NAT + Host-only

Recommended for smooth operation:
├── RAM: 2048 MB (2GB)  
├── Storage: 12-15 GB
├── CPU: 2 cores
└── Network: Bridged (if needed)
System Optimization:


bash
# Disable unnecessary services
sudo systemctl disable bluetooth
sudo systemctl disable avahi-daemon

# Clean package cache
sudo apt autoremove
sudo apt autoclean

# Clear logs (if getting too large)
sudo journalctl --vacuum-time=7d

12. 🔧 Troubleshooting ve Problem Çözme
Common Issues ve Çözümleri:
1. SSH Connection Problems:


bash
# SSH service kontrolü
sudo systemctl status ssh
sudo systemctl restart ssh

# Port kontrolü
sudo ss -tlnp | grep :4242

# Firewall kontrolü
sudo ufw status
sudo ufw allow 4242/tcp
2. Password Policy Issues:


bash
# pwquality test
echo "testpass" | pwscore

# PAM configuration kontrolü
sudo pamtester login username authenticate

# Password aging kontrolü
sudo chage -l username
3. Sudo Problems:


bash
# Sudo configuration test
sudo visudo -c

# Log kontrolü
sudo tail /var/log/sudo/sudo.log
sudo tail /var/log/auth.log
4. LVM Issues:


bash
# LVM status kontrolü
sudo vgdisplay
sudo lvdisplay
sudo pvdisplay

# Disk space kontrolü
df -h
sudo lvs
5. Monitoring Script Problems:


bash
# Script syntax kontrolü
bash -n /root/monitoring.sh

# Cron job kontrolü
sudo crontab -l
sudo systemctl status cron

# Wall command test
echo "Test message" | wall
Log Files for Debugging:


bash
# System logs
sudo tail -f /var/log/syslog
sudo tail -f /var/log/auth.log
sudo tail -f /var/log/kern.log

# Service-specific logs
sudo journalctl -u ssh
sudo journalctl -u cron
sudo journalctl -u ufw

13. 🎁 Bonus Part Detayları
WordPress Setup with lighttpd, MariaDB, PHP:
1. Lighttpd Installation:


bash
sudo apt update
sudo apt install lighttpd

# Lighttpd configuration
sudo nano /etc/lighttpd/lighttpd.conf

# Enable modules
sudo lighttpd-enable-mod fastcgi
sudo lighttpd-enable-mod fastcgi-php
2. MariaDB Setup:


bash
sudo apt install mariadb-server
sudo mysql_secure_installation

# Create WordPress database
sudo mysql -u root -p
CREATE DATABASE wordpress;
CREATE USER 'wpuser'@'localhost' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON wordpress.* TO 'wpuser'@'localhost';
FLUSH PRIVILEGES;
EXIT;
3. PHP Installation:


bash
sudo apt install php-fpm php-mysql php-curl php-gd php-xml

# PHP configuration
sudo nano /etc/php/7.4/fpm/php.ini
4. WordPress Installation:


bash
cd /var/www/html
sudo wget https://wordpress.org/latest.tar.gz
sudo tar -xzf latest.tar.gz
sudo chown -R www-data:www-data wordpress/
5. Additional Service - Fail2ban:


bash
# Fail2ban kurulumu
sudo apt install fail2ban

# SSH protection
sudo nano /etc/fail2ban/jail.local
[sshd]
enabled = true
port = 4242
maxretry = 3
bantime = 600
Bonus Partitioning Structure:


# lsblk output for bonus
NAME                MAJ:MIN RM  SIZE RO TYPE  MOUNTPOINT
sda                   8:0    0 30.8G  0 disk
├─sda1                8:1    0  500M  0 part  /boot
└─sda2                8:2    0   1K  0 part
  └─sda5              8:5    0 30.3G  0 part
    └─sda5_crypt    254:0    0 30.3G  0 crypt
      ├─LVMGroup-root 254:1    0  10G  0 lvm   /
      ├─LVMGroup-swap 254:2    0  2.3G  0 lvm   [SWAP]
      ├─LVMGroup-home 254:3    0   5G  0 lvm   /home
      ├─LVMGroup-var  254:4    0   3G  0 lvm   /var
      ├─LVMGroup-srv  254:5    0   3G  0 lvm   /srv
      ├─LVMGroup-tmp  254:6    0   3G  0 lvm   /tmp
      └─LVMGroup-var--log 254:7  0   4G  0 lvm   /var/log

14. 📤 Proje Teslimi ve Signature
Signature Alma İşlemi:
VirtualBox için:


bash
# Windows
certUtil -hashfile Born2beRoot.vdi sha1

# Linux/macOS
shasum Born2beRoot.vdi
sha1sum Born2beRoot.vdi
UTM için (Mac M1):


bash
shasum Born2beRoot.utm/Images/disk-0.qcow2
Signature.txt Dosyası:


bash
# Git repository'nizin root'unda
echo "6e657c4619944be17df3c31faa030c25e43e40af" > signature.txt
git add signature.txt
git commit -m "Add signature.txt"
git push
⚠️ Önemli Uyarılar:
* Snapshot kullanımı YASAK!
* VM dosyasını Git'e upload etmeyin
* Signature değişebilir, defense öncesi kontrol edin
* VM'i klonlayabilir veya save state kullanabilirsiniz

🎯 Final Checklist
✅ Mandatory Requirements:
* VirtualBox/UTM'de Debian/Rocky kurulu
* Graphical interface YOK
* En az 2 encrypted LVM partition
* SSH port 4242'de çalışıyor
* Root SSH login yasak
* UFW/firewalld aktif, sadece 4242 açık
* Strong password policy aktif
* Sudo configuration doğru
* User42 ve sudo grupları mevcut
* Monitoring script çalışıyor
* Cron job her 10 dakikada çalışıyor
* AppArmor/SELinux aktif
✅ Defense Preparation:
* Tüm komutları ezberledim
* Teorik soruları biliyorum
* Yeni user oluşturabilirim
* Password policy test edebilirim
* Monitoring script açıklayabilirim
* Firewall kuralları değiştirebilirim
✅ Bonus Requirements (Opsiyonel):
* WordPress kurulumu tamamlandı
* Lighttpd + MariaDB + PHP çalışıyor
* Ek servis (Fail2ban) kuruldu
* Bonus partitioning yapıldı

📝 Kapsamlı Özet
🔑 Projenin Temel Amacı:
Born2beRoot, sistem yönetimi temellerini öğreten bir projedir. Sanal makine üzerinde güvenli Linux server kurarak, network security, user management, system monitoring ve security hardening konularında pratik deneyim kazandırır.
🏗️ Projenin Mimarisi:


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
🛡️ Güvenlik Katmanları (Defense in Depth):


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

✅ ULTIMATE FINAL CHECKLIST
🖥️ PHASE 1: VM KURULUM VE TEMEL YAPILANDIRMA


bash
□ VirtualBox/UTM kurulumu tamamlandı
□ Debian 12 veya Rocky 9 ISO'su indirildi
□ VM oluşturuldu (min 1GB RAM, 8GB disk)
□ Network: NAT ayarlandı
□ İşletim sistemi kuruldu (NO GUI!)
□ Encryption aktif edildi (LUKS)
□ LVM ile partitioning yapıldı (min 2 partition)
□ Hostname: [login]42 formatında ayarlandı
□ Root password güçlü şekilde ayarlandı
Doğrulama Komutları:


bash
hostnamectl                    # Hostname kontrol
lsblk                         # Partition yapısı
sudo fdisk -l                 # Disk bilgisi
df -h                         # Mount points
🔐 PHASE 2: USER YÖNETİMİ VE GÜVENLİK


bash
□ Normal user oluşturuldu (login adınız)
□ User, sudo grubuna eklendi
□ User42 grubu oluşturuldu  
□ User, user42 grubuna eklendi
□ Strong password policy yapılandırıldı (/etc/login.defs)
□ PAM pwquality ayarları yapıldı
□ Tüm mevcut user'ların şifreleri değiştirildi
□ Password aging kuralları uygulandı
Doğrulama Komutları:


bash
id $(whoami)                  # User groups
groups $(whoami)              # Group membership
sudo chage -l $(whoami)       # Password aging
getent group user42           # user42 group members
🛡️ PHASE 3: SUDO YAPILANDIRMASI


bash
□ /etc/sudoers.d/sudo_config dosyası oluşturuldu
□ passwd_tries=3 ayarlandı
□ Custom badpass_message ayarlandı
□ logfile="/var/log/sudo/sudo.log" ayarlandı
□ log_input,log_output aktif edildi
□ iolog_dir="/var/log/sudo" ayarlandı
□ requiretty aktif edildi
□ secure_path ayarlandı
□ /var/log/sudo/ dizini oluşturuldu
Doğrulama Komutları:


bash
sudo visudo -c                # Syntax kontrol
sudo -l                       # User sudo permissions
ls -la /var/log/sudo/         # Log directory
sudo cat /etc/sudoers.d/sudo_config  # Config file

🌐 PHASE 4: SSH VE NETWORK GÜVENLİĞİ


bash
□ SSH service kuruldu ve aktif
□ SSH port 4242'ye değiştirildi
□ PermitRootLogin no ayarlandı
□ PasswordAuthentication yes (proje gereği)
□ PermitEmptyPasswords no ayarlandı
□ MaxAuthTries 3 ayarlandı
□ SSH service restart edildi
□ SSH ile test bağlantısı yapıldı
Doğrulama Komutları:


bash
sudo systemctl status ssh     # SSH service status
sudo ss -tlnp | grep :4242   # Port listening kontrol
ssh [user]@localhost -p 4242  # Local test connection
🔥 PHASE 5: FIREWALL YAPILANDIRMASI


bash
□ UFW/firewalld kuruldu
□ Default incoming: DENY ayarlandı
□ Default outgoing: ALLOW ayarlandı
□ Port 4242/tcp açıldı
□ Firewall aktif edildi
□ Diğer tüm portlar kapatıldı
□ Rules test edildi
Doğrulama Komutları:


bash
sudo ufw status numbered      # UFW rules (Debian)
sudo firewall-cmd --list-all  # Firewalld rules (Rocky)
nmap localhost                # Port scan test
🔒 PHASE 6: GÜVENLİK MODÜLLERİ


bash
□ AppArmor aktif (Debian) VEYA SELinux aktif (Rocky)
□ Startup'ta otomatik başlatma ayarlandı
□ Security module policies kontrol edildi
□ Gerekli profiles/contexts yüklendi
Doğrulama Komutları:


bash
# Debian için:
sudo apparmor_status
sudo systemctl status apparmor

# Rocky için:
sestatus
getenforce
📊 PHASE 7: MONİTORİNG SİSTEMİ


bash
□ monitoring.sh script yazıldı
□ Script /root/ dizinine yerleştirildi
□ Execute permission verildi (chmod +x)
□ Script test edildi (manuel çalıştırma)
□ Cron job oluşturuldu (*/10 * * * *)
□ Wall komutu ile broadcast test edildi
□ Script'in tüm bilgileri doğru gösterdiği kontrol edildi
Monitoring Script Requirements:


bash
□ Architecture ve kernel version
□ Physical CPU sayısı
□ Virtual CPU sayısı  
□ RAM kullanımı (current/total ve %)
□ Disk kullanımı (current/total ve %)
□ CPU load yüzdesi
□ Son reboot tarihi/saati
□ LVM aktif mi? (yes/no)
□ TCP bağlantı sayısı
□ Login yapan user sayısı
□ IPv4 address ve MAC address
□ Sudo komut sayısı
Doğrulama Komutları:


bash
sudo /root/monitoring.sh      # Manuel çalıştırma
sudo crontab -l               # Cron job kontrol
sudo systemctl status cron    # Cron service status
📋 PHASE 8: DEFENSE HAZIRLIĞI


bash
□ Tüm teorik konular öğrenildi
□ Komutlar ezberlenid
□ Password policy test senaryoları hazırlandı
□ User oluşturma/silme işlemleri pratik edildi
□ Firewall rule değişiklik işlemleri pratik edildi
□ Monitoring script açıklaması hazırlandı
□ Troubleshooting senaryoları gözden geçirildi
□ Log dosyaları lokasyonları öğrenildi
🎁 BONUS PHASE: EK ÖZELLIKLER (İsteğe Bağlı)


bash
□ Bonus partitioning yapısı oluşturuldu
□ Lighttpd web server kuruldu
□ MariaDB database kuruldu  
□ PHP kuruldu ve yapılandırıldı
□ WordPress kuruldu ve yapılandırıldı
□ Ek servis seçildi ve kuruldu (Fail2ban önerilir)
□ Bonus için gerekli portlar firewall'da açıldı
□ Tüm bonus servisler test edildi
📤 FINAL PHASE: TESLİM HAZIRLIĞI


bash
□ VM tamamen kapatıldı
□ Snapshot kontrol edildi (YASAK!)
□ VM signature alındı (SHA1)
□ signature.txt dosyası oluşturuldu
□ Git repository'ye yüklendi
□ VM yedeği oluşturuldu (clone)
□ Defense tarihi öncesi final kontrol yapıldı

🎯 SON KONTROL LİSTESİ - DEFENSE ÖNCESİ
⚡ 5 DAKİKALIK HIZ KONTROL:


bash
# 1. System bilgileri
uname -a && hostnamectl && lsblk

# 2. User ve group kontrol  
id $(whoami) && groups $(whoami) && getent group user42

# 3. SSH ve Firewall
sudo systemctl status ssh && sudo ufw status

# 4. Password policy test
sudo chage -l $(whoami)

# 5. Sudo configuration
sudo visudo -c && sudo -l

# 6. Security modules
sudo apparmor_status || sestatus

# 7. Monitoring script
sudo /root/monitoring.sh

# 8. Cron job
sudo crontab -l

🚨 KRİTİK HATIRLATMALAR:
1. SNAPSHOT YASAK - Defense sırasında kontrol edilir
2. VM'İ GIT'E YÜKLEME - Sadece signature.txt yükle
3. ROOT LOGIN - SSH ile root girişi kapatılmalı
4. PORT 4242 - SSH sadece bu portta çalışmalı
5. PASSWORD POLICY - Tüm user'lar için geçerli olmalı
6. CRON JOB - 10 dakikada bir çalışmalı
7. FIREWALL - Sadece 4242 portu açık olmalı
8. LVM - En az 2 encrypted partition olmalı
9. 
📚 DEFENSE SORULARI HAZIRLIK:
Temel Sorular:
* Virtual Machine nedir?
* LVM avantajları nelerdir?
* SSH neden port 4242'de?
* UFW nedir, nasıl çalışır?
* Sudo neden kullanılır?
* AppArmor/SELinux ne işe yarar?
* Password policy neden önemli?
Pratik Gösterimler:
* Yeni user oluştur ve gruba ekle
* Firewall rule ekle/sil
* Password değiştir (policy test)
* Monitoring script'i açıkla
* Log dosyalarını göster

🏆 BAŞARI GARANTİSİ
Bu checklist'i tamamen tamamladıysanız: ✅ %100 Mandatory part tamamlanmış ✅ Defense'da tüm sorular cevaplanabilir ✅ Pratik gösterimler yapılabilir ✅ Troubleshooting yapılabilir ✅ Bonus point alınabilir
Final Tavsiye: Defense öncesi tüm listeyi bir kez daha gözden geçirin ve her maddeyi test edin. Başarılar! 🚀🎓
