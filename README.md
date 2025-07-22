# Born2beRoot Yol Haritası ve Yapılacaklar Listesi
🎯 **Proje Genel Bakış - Version 3.6**  
Born2beroot, sistem yönetimi ve güvenlik temellerini öğretmeyi amaçlayan bir projedir. Sanal makine üzerinde minimum service ile güvenli bir server kurulumu yapacaksınız.  
⚠️ **ÖNEMLİ**: Hiçbir grafik arayüz (X.org vb.) kurulmayacak - aksi halde 0 puan!

---

## 📋 Ön Hazırık (Başlamadan Önce Öğrenilecekler)

### Temel Kavramlar:
- **Sanal Makine nedir?** - Fiziksel bilgisayar üzerinde çalışan sanal bilgisayar
- **Linux Dağıtımları** - Debian vs Rocky Linux farkları
- **Root vs Normal User** - Yetki seviyeleri ve güvenlik
- **SSH nedir?** - Uzaktan güvenli bağlantı protokolü
- **Firewall kavramı** - Ağ güvenliği ve port kontrolü

### Öğrenilecek Komutlar:
- **bash# Sistem bilgisi**  
  `uname -a`, `hostnamectl`, `lsb_release -a`
- **Kullanıcı yönetimi**  
  `adduser`, `usermod`, `groups`, `id`, `su`, `sudo`
- **Dosya sistemi**  
  `ls -la`, `chmod`, `chown`, `df -h`, `lsblk`
- **Ağ yönetimi**  
  `ip addr`, `ss -tuln`, `systemctl status`
- **Paket yönetimi (Debian)**  
  `apt update`, `apt install`, `apt list`

---

## 🚀 ADIM 1: Sanal Makine Kurulumu

### Yapılacaklar:
1. **VirtualBox indirip kur**
2. **Debian ISO dosyasını indir** (stable sürüm)
3. **Yeni sanal makine oluştur**
   - RAM: En az 1GB (2GB önerilir)
   - Disk: 8GB (12GB güvenli olur)
   - Network: NAT + Host-only Adapter
4. **Debian kurulumunu başlat**

### Kurulum Sırasında Dikkat Edilecekler:
- Mandatory: En az 2 encrypted partition (LVM kullanarak)
- ÖNEMLİ: Hiçbir grafik arayüz kurma! (X.org forbidden)
- **Root password** güçlü belirle
- `login42` formatında user oluştur (örn: sudenaz42)
- SSH server kurulumunu seç
- Debian: AppArmor aktif olmalı startup'ta
- Minimal server kurulumu (hiç desktop environment yok)

---

## 🔧 ADIM 2: Temel Sistem Yapılandırması

### Hostname ve Network:
- Hostname'i `sudenaz42` formatında ayarla (defense sırasında değiştireceksin)
- SSH servisini port 4242'de yapılandır
- AppArmor'ın startup'ta aktif olduğunu kontrol et

### Kullanıcı Yönetimi:
- `sudenaz42` user'ını `user42` ve `sudo` gruplarına ekle
- Root login'i SSH'dan devre dışı bırak
- Defense sırasında yeni user oluşturup gruba ekleme testi olacak!

---

## 🛡️ ADIM 3: Güvenlik Yapılandırması

### Password Policy (Çok Spesifik!)
- `/etc/login.defs` ve `/etc/pam.d/common-password`
- Password expiry: 30 gün
- Minimum days before change: 2 gün
- Warning before expiry: 7 gün
- Minimum length: 10 karakter
- Zorunlu: 1 büyük harf, 1 küçük harf, 1 rakam
- Yasak: Ardışık 3 aynı karakter (aaa, 111 vb.)
- Yasak: Username içermemeli
- Root hariç: Önceki passworddan en az 7 farklı karakter
- Önemli: Tüm mevcut passwordleri policy'den sonra değiştir!

### Sudo Yapılandırması (/etc/sudoers) - Çok Spesifik!
- Attempts: Maximum 3 deneme hakkı
- Custom error message: Kendi belirlediğin hata mesajı
- Logging: Input ve output'ları `/var/log/sudo/` klasörüne kaydet
- TTY requirement: TTY mode aktif olmalı
- Secure path: `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin`

### SSH Güvenliği (/etc/ssh/sshd_config)
- Port'u 4242 olarak değiştir
- Root login'i devre dışı bırak
- Password authentication'ı aktif tut
- SSH servisini yeniden başlat

### Firewall (UFW)
- UFW'yi kur ve aktif et
- Sadece 4242 portunu aç
- Default deny incoming policy
- Firewall durumunu kontrol et

---

## 📊 ADIM 4: Monitoring Script

### Script Gereksinimleri (monitoring.sh) - **EXACT FORMAT**
Bu bilgileri tam olarak bu sırada göstermeli:
- Architecture: `uname -a` bilgisi
- CPU physical: Fiziksel işlemci sayısı
- vCPU: Sanal işlemci sayısı
- Memory Usage: Kullanılan/Toplam MB (yüzde)
- Disk Usage: Kullanılan/Toplam (yüzde)
- CPU load: İşlemci yükü yüzdesi
- Last boot: Son restart tarihi ve saati
- LVM use: yes/no
- Connections TCP: ESTABLISHED bağlantı sayısı
- User log: Giriş yapan kullanıcı sayısı
- Network: IP adresi ve MAC adresi
- Sudo: Toplam sudo komut sayısı

**Örnek çıktı formatı:**
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

## Cron Job Yapılandırması

- Script'i her 10 dakikada çalıştır (cron)
- Server startup'ta otomatik başlat
- Tüm terminallere broadcast (`wall` komutu)
- Defense sırasında script'i durdurmayı bileceksin (cron'u durdur)

---

## 🎁 BONUS KISMASI - Sadece Mandatory Perfect İse!

**⚠️ UYARI:** Bonus sadece mandatory kısım MÜKEMMEL ise değerlendirilir!

### Partition Yapısı (Bonus)
- Spesifik partition yapısını oluştur (subject'teki diyagram)

### WordPress Stack
- Lighttpd web server (Apache/Nginx yasak!)
- MariaDB database
- PHP
- WordPress kurulumu ve yapılandırması

### Ek Servis (Kendi Seçimin)
- Faydalı bir servis kur (NGINX/Apache2 hariç)
- Defense'da seçimini gerekçelendir
- Ek portlar açabilirsin (UFW kurallarını güncelle)

#### Bonus servis önerileri:
- Fail2ban (güvenlik)
- Netdata (monitoring)
- FTP server (vsftpd)
- Mail server
- Git server (Gitea)

---

## ✅ Test ve Sunum Hazırlığı

### Sistem Testleri
- Tüm servislerin çalıştığını kontrol et
- Password policy'nin çalıştığını test et
- SSH bağlantısını test et (port 4242)
- Sudo loglarını kontrol et
- Monitoring script'in düzgün çalıştığını kontrol et
- Firewall kurallarını test et

### Defense Hazırlığı - BİLMEN GEREKEN SORULAR
**Subject'ta belirtilen önemli sorular:**
- Debian seçiminin nedeni nedir?
- apt vs aptitude farkları nelerdir?
- AppArmor nedir ve nasıl çalışır?
- SSH nasıl çalışır ve neden güvenlidir?
- UFW nedir ve nasıl yapılandırılır?
- Sudo sistemi nasıl çalışır?
- Password policy neden önemlidir?
- LVM nedir ve avantajları?
- Cron job nedir ve monitoring script nasıl çalışır?
- Script'i nasıl durdurursun? (cron olmadan)
- Virtual Machine avantajları ve dezavantajları?

### Defense Sırasında YAPILACAKLAR
- Yeni user oluştur ve gruba ekle
- Hostname değiştir
- SSH ile yeni user'la bağlan
- Monitoring script'i durdur
- UFW kurallarını göster
- Sudo loglarını göster

### Sunum Sırasında Gösterilecekler
- Hostname kontrolü: `hostnamectl`
- User ve group kontrolü: `groups [username]`
- SSH servis durumu: `systemctl status ssh`
- UFW durumu: `sudo ufw status`
- Password policy dosyaları: `cat /etc/login.defs`
- Sudo yapılandırması: `sudo visudo`
- Cron jobs: `crontab -l`
- Monitoring script çalışması

---

## ⚠️ KRITIK UYARILAR - SIFIR PUAN ALMAMAK İÇİN!
- Hiçbir grafik arayüz kurma - X.org yasak → 0 puan
- Snapshot kullanma - Detect edilirse → 0 puan
- `signature.txt` doğru olmalı - VM signature ile aynı değilse → 0 puan
- Mandatory mükemmel değilse bonus değerlendirilmez
- VM'i Git'e koyma - Sadece `signature.txt` upload et

---

## 📁 Teslim (Submission)
1. VM'in .vdi dosyasının SHA1 signature'ını al
2. `signature.txt` dosyasını root dizinde sakla
3. Sadece bu dosyayı Git'e push et

### Signature alma komutları:
- **Linux:** `sha1sum your_vm.vdi`
- **Windows:** `certUtil -hashfile your_vm.vdi sha1`
- **Mac:** `shasum your_vm.vdi`

---

## SSH Bağlantı Problemleri
- Port forwarding ayarları (VirtualBox Network)
- SSH config dosyası syntax hatası
- Firewall port bloklama

## Sudo Problemleri
- `/etc/sudoers` syntax error (visudo kullan)
- User'ı sudo grubuna eklemeyi unutma
- TTY requirement sorunları

## Script Problemleri
- Execute permission (`chmod +x monitoring.sh`)
- Cron environment variables
- Wall komutu permission sorunları

---

## 💡 Önemli İpuçları
- Her değişiklik öncesi backup al - Özellikle config dosyaları
- Adım adım ilerle - Bir adımı tamamlamadan diğerine geçme
- Logları takip et - `/var/log/` altındaki dosyaları kontrol et
- Test et - Her yapılandırma sonrası mutlaka test et
- Dokümante et - Yaptığın değişiklikleri not al

---

## 📚 Faydalı Kaynaklar
- [Debian Documentation](https://www.debian.org/doc/)
- [UFW Manual](man ufw)
- [SSH Config](man sshd_config)
- [Crontab](man crontab)
- Born2beroot subject dosyası (42 intra)

**Not:** Bu liste genel bir rehberdir. 42'nin güncel subject dosyasını mutlaka kontrol et ve ona göre ilerle!
