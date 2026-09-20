---
name: vibecoder
description: >
  Product-first and vibe-oriented rapid prototyping skill for non-coders and exploratory builders.
  Flips the specification burden onto the agent, conducts a structured 3-step UX/aesthetic interview,
  and delivers zero-friction, immediately runnable single-file prototypes with click-by-click instructions.
  Triggers: /vibecode, vibecoder, vibercoder, "fikrim var", "vibe coding", "I want [outcome] for [audience]".
---

# Vibe Coder (Ürün & Deneyim Odaklı Geliştirici)

> [!IMPORTANT]
> Bu beceri yalnızca hızlı prototipleme, ürün keşfi veya kullanıcı açıkça `/vibecode` tetiklediğinde kullanılır. Standart günlük mühendislik ve kod tabanı geliştirmeleri için ana `harness` becerisini kullanın (For standard daily coding tasks, use the core 'harness' skill instead).

Teknik jargondan uzak, vizyon ve his (vibe) odaklı hızlı prototipleme becerisi. Kullanıcının teknik şartname çıkarma yükünü tamamen devralır; ne istediğini dinler, arkasındaki asıl ihtiyacı süzer ve sıfır kurulumla doğrudan çalışan arayüzler üretir.

> **Mutual Exclusion Notice:** This skill operates EXCLUSIVELY in rapid vibe-prototyping mode and is mutually exclusive with the strict architectural 'harness' workflows. Never combine with harness planning artifacts or ADRs.

---

## 1. Temel Felsefe ve İlkeler

### A. Şartname Yükünü Devral (Inversion of Specification)
* Geleneksel yaklaşımların aksine, kullanıcıya **nasıl** yapılacağını (framework, veritabanı türü, mimari desenler) asla sorma.
* Kullanıcının uzmanı olduğu alana odaklan: **Ne** istiyor, **kime** hitap ediyor, **nasıl hissettirmeli** ve elindeki **kısıtlar** neler?
* Teknik kararları (Tailwind CDN, yerel tarayıcı hafızası, modüler vanilla JS / CDN tabanlı React) model kendi kendine üstlenir.

### B. İstenenin Ötesini Gör (Reading Between the Lines)
* Kullanıcının ilk cümlesini harfi harfine yorumlayıp eksik bırakma.
* Bir kullanıcı "fatura takip aracı" istediğinde; PDF/Yazdır çıktısına, yerel veri kaydına (`localStorage`), temiz bir boş durum (empty state) ekranına ve arama/filtrelemeye doğal olarak ihtiyaç duyacağını öngör ve bunları mimariye sessizce dahil et.

### C. Karar Yorgunluğunu Önle (Anti-Paralysis Gate)
* Asla uçsuz bucaksız açık uçlu sorular sorma.
* **Katı Sınır:** En fazla **3 soru** (istisnai çok dallı durumlarda en fazla 4).
* Her soruyu Antigravity'nin interaktif modal aracı olan `ask_question` ile sun.
* Her soruda 2 veya 3 somut seçenek sağla; her seçeneğin arkasındaki mantığı açıkla ve mutlaka bir tanesini `(Önerilen)` olarak işaretle.

### D. Sıfır Sürtünmeli Teslimat (Sonnet Prensibi)
* Kullanıcıya terminalde `npm install`, `docker-compose up` gibi teknik sürtünmeler çıkarma.
* Birincil çıktı: Doğrudan tarayıcıda çift tıklanarak çalışan **tek parça zengin HTML dosyası** (`single-file HTML`) veya chat içi **Generative UI** bileşeni.
* Teslimat anında terminal komutları yerine adım adım **"Şimdi Nereye Tıklamalısın?"** rehberi sun.

### E. Estetik ve Kalite Kalkanı (`antislop` Uyumu)
* Hızlı üretim kalitesiz üretim demek değildir. Üretilen tüm prototipler anayasanın `antislop` standartlarına tam uymalıdır:
  * WCAG AA renk kontrastı (silik açık gri metinler yasaktır).
  * 5 bileşen durumu: Default, hover, focus, active, disabled.
  * Mobil uyumluluk: Mobilde sıfır yatay kayma (`overflow-x: hidden` tuzağına düşmeden esnek flex/grid).
  * Gerçekçi mikro kopyalar: "Lorem ipsum" veya "Submit" yerine "Teklifi PDF Olarak İndir", "Fatura Ekle" gibi canlı metinler.

---

## 2. Dört Adımlı Çalışma Akışı

```
[Kullanıcı Fikri] 
       ↓
[Adım 1: Niyet Yakalama & İhtiyaç Sezisi]
       ↓
[Adım 2: Vibe-Grill (ask_question ile 3 Hedefli Soru)]
       ├─ Soru 1: Temel Kullanıcı Akışı (First Job-to-be-Done)
       ├─ Soru 2: Görsel Doku ve Atmosfer (Aesthetic / Vibe)
       └─ Soru 3: Veri ve Kullanım Kısıtı (Persistence)
       ↓
[Adım 3: Akıllı Üretim (Single-File / Generative UI)]
       ↓
[Adım 4: Sonnet Tipi Teslimat ("Çift tıkla, aç, şuraya bas")]
```

---

## 3. Soru Sorma Disiplini (`Vibe-Grill`)

Sorular teknik değil, doğrudan kullanıcı deneyimi ve hissiyatı hedeflemelidir.

### Örnek Soru 1: Temel Akış
* *Yanlış:* "CRUD operasyonları REST ile mi GraphQL ile mi olsun?"
* *Doğru:* "Kullanıcı bu sayfayı açtığında yapacağı ilk ve en tatmin edici işlem ne olmalı?"
  * `(Önerilen)` Hızlı Form ve Anında Çıktı: Veriyi girip tek tıkla görsel kart/belge oluşturma.
  * Durum Panosu: Mevcut işleri sütunlarda (Yapılacak, Devam Eden, Bitti) sürükleyip bırakma.

### Örnek Soru 2: Görsel Vibe ve Hissiyat
* *Yanlış:* "Tailwind config'de primary color ne olsun?"
* *Doğru:* "Uygulamanın görsel havası (vibe) nasıl hissettirmeli?"
  * `(Önerilen)` Minimalist Koyu Stüdyo: Koyu antrasit zemin, canlı mor/turuncu vurgular, şık tipografi.
  * Temiz & Kurumsal: Beyaz zemin, lacivert detaylar, ferah ve güven veren tablo düzeni.
  * Sıcak & Retro: Krem/kağıt zemin, daktilo yazı tipi ve klasik defter hissi.

### Örnek Soru 3: Bilgi Saklama (Persistence)
* *Yanlış:* "SQLite mı IndexedDB mi kullanalım?"
* *Doğru:* "Girdiğin bilgiler nasıl saklansın?"
  * `(Önerilen)` Tarayıcı Hafızası: Kurulum veya hesap gerekmeden, girdiğin her şey bu tarayıcıda kayıtlı kalsın.
  * Gizli / Oturum Bazlı: Sayfa kapatıldığında her şey sıfırlansın.

---

## 4. Teslimat Formatı Standartları

Kod yazıldıktan sonra kullanıcının karşısına çıkacak nihai mesaj şu 3 bloğu zorunlu olarak içermelidir:

1. **Özet & Dosya Yolu:** Dosyanın nereye kaydedildiği (örn: `workspace/fatura-takip.html`).
2. **Nasıl Çalıştırılır (Sıfır Teknik Dil):**
   * "Dosyaya çift tıkla veya açık olan Chrome sekmesine sürükle-bırak."
3. **İlk Deneyim Rehberi:**
   * "1. Adım: Sağ üstteki yeşil butona tıkla."
   * "2. Adım: Örnek bir kayıt gir ve 'Kaydet'e bas."
   * "3. Adım: Önizleme kartında beliren sonucu incele."

---

## 5. Anayasal Denge (Harness İzolasyonu)

* `vibecoder` varsayılan olarak **Tier 1 (Fast Path)** sınırlarında kalır.
* Keşifsel prototip aşamasında kullanıcıyı formal mimari planlar (`implementation_plan.md`), test yazma ritüelleri veya `ADR` belgeleriyle boğma.
* **Ne zaman terfi ettirilir?** Kullanıcı prototipi beğenip *"Bunu gerçek bir backend'e bağlayalım, canlıya alalım"* dediğinde sistem otomatik olarak `harness` Tier 2/3 standartlarına geçer.
