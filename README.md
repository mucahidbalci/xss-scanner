# 🚀 SecAudit Pro (XSS & Vulnerability Scanner)

⚠️ **Warning!** Still under development; do not expect a fully functional version.
⚠️ **UYARI!** Henüz Geliştirilme Aşamasındadır v0.2 gerçek sürüm değildir.

---

## ⚡ Powered by mucahidbalci
*Mücahid Balcı tarafından desteklenmektedir.*

* 🌐 **WEB:** [mucahidbalci.github.io](https://mucahidbalci.github.io)
* 📸 **CONTACT ME:** [@mucahidbalci](https://instagram.com/mucahidbalci)
* 🔗 **SOCIAL MEDIA:** [guns.lol/mucahh1d](https://guns.lol/mucahh1d)
* 💰 **Support me via my crypto wallet:** `bc1qactkh6r8rfnghpqjdvr3nnl4ht0psec63ehy9z`

---

## 📋 Proje Hakkında (About the Project)

SecAudit Pro; sızma testleri, yerel ağ denetimleri ve siber güvenlik analizleri için geliştirilmiş, modern ve yüksek performanslı bir ağ zafiyet tarama (Port Scanner) ve web güvenlik otomasyon yazılımıdır. 

Arka planda çalışan 150 thread'li asenkron multithreading motoru sayesinde altyapı zafiyetlerini saniyeler içinde tespit ederken; `customtkinter` tabanlı pencereli grafik arayüzü (GUI) ile son derece konforlu bir analiz deneyimi sunar.

## 🚀 Öne Çıkan Gelişmiş Özellikler

* **🎨 Modern CustomTkinter GUI:** Sıkıcı CLI ekranları yerine, karanlık mod destekli, optimize edilmiş ve kullanıcı dostu pencereli modern tasarım.
* **⚡ 150 Thread Gücünde Multithreading:** Arka planda aynı anda 150 iş parçacığı yürüterek tüm alt ağları (Subnet) ve binlerce portu saniyeler içinde tarar.
* **🌐 Gelişmiş Hedef Çözümleme (Target Resolution):** Tekil IP adreslerini, alan adlarını (Domain) veya CIDR formatındaki ağ aralıklarını otomatik olarak parse eder.
* **📊 Banner Grabbing (Versiyon Tespiti):** HTTP GET istekleri ve raw socket analizleri ile sunucudaki yazılım versiyonlarını (`Server: nginx/1.18.0` gibi) canlı çeker.
* **👁️ Canlı Sistem Logları:** Entegre `queue` yapısı sayesinde tarama esnasında arayüz asla kilitlenmez (freeze olmaz). Arka plan durumları canlı log alanından anlık izlenebilir.
* **📥 Excel Uyumlu Raporlama:** Tarama sonuçlarını tek tıkla zaman damgalı `.csv` rapor dosyası olarak dışarı aktarır.

## 🛠️ Sistem Gereksinimleri & Kurulum

Yazılımın çalışması için sisteminizde **Python 3.8** veya üzeri bir sürümün yüklü olması gerekmektedir.

```bash
# Bağımlılıkları yükleyin
pip install -r requirements.txt

# Uygulamayı başlatın
python main.py
```

## 📜 Sürüm Geçmişi (Changelog)
Projenin v0.1 ilkel prototipinden v1.0 Enterprise/SaaS seviyesindeki nihai şaheserine kadar olan tüm kronolojik gelişimi ve detaylı sürüm notlarını incelemek için **[CHANGELOG.md](./CHANGELOG.md)** dosyasını ziyaret edebilirsiniz.

## ⚠️ Yasal Uyarı / Disclaimer

**TR:** Bu yazılım tamamen eğitim, yerel ağ güvenliği denetimleri ve yasal sızma testleri süreçlerinde altyapı analizi yapmak amacıyla geliştirilmiştir. Yetkisiz veya izinsiz ağlar üzerinde kullanımı tamamen kullanıcının sorumluluğundadır. Geliştirici (Mücahid Balcı), oluşabilecek yasal sorunlardan veya kötüye kullanımlardan dolayı hiçbir sorumluluk kabul etmez.

**EN:** This software is developed strictly for educational purposes, local network auditing, and legal penetration testing. Any unauthorized use on external networks is entirely the responsibility of the user. The developer (Mücahid Balcı) assumes no liability for any misuse or damage caused by this program.
