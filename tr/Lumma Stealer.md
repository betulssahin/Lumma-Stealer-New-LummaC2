# Lumma Stealer

Lumma Stealer, 2022 yılından beri faaliyet gösteren bilgi çalan (infostealer) zararlı yazılımdır. Araştırmalara göre Lumma ailesine ait zararlı yazılımların kullanımı son yıllarda artış göstermektedir. Lumma hizmet olarak satışa sunulan MaaS (Malware as a Service) modelini benimsemiş bir zararlı yazılımdır. Bu model sayesinde teknik bilgilere sahip olmayan kişiler bile bu tür zararlı yazılımlara kolayca erişebilmekte ve yayılmasına sebep olabilmektedir. 

![Son Bir Yıldaki Zararlı Yazılım Trendi (ANY.RUN)](/img/1.png)

_Lumma_ _Stealer_, hedeflediği sistemlerden tarayıcı bilgilerini, kripto para cüzdan bilgilerini, sistem bilgilerini ele geçirmeyi hedeflemektedir. Ele geçirdiği bu bilgileri özel C&C (Komut ve Kontrol) sunucularına göndererek bu bilgileri çalmayı amaçlamaktadır.

Bir hizmet olarak satışa sunulduğu için yayılma yöntemleri çeşitlilik göstermektedir. **Sahte** **CAPTCHA** sayfaları oluşturarak yayılmak son zamanlarda en sık kullanılan yöntemlerdendir. Bunun yanında tehdit aktörleri Discord gibi platformların **CDN’lerini** kullanarak ya da **crack** yazılımlar aracılığıyla _Lumma_ _Stealer’ı_ dağıtmaktadırlar.

Yapılan araştırmalara göre 2025 yılının ilk çeyreğinde, 2024 yılı boyunca bildirilen _Lumma_ kaynaklı saldırıların yaklaşık iki katı kadar saldırı tespit edilmektedir.

![Yıllara Göre Lumma Stealer ile İlişkili Saldırıların Sayısı (Ontinue)](/img/2.png)

Lumma ailesi, _Lumma_ _Stealer_ zararlı yazılımını geliştirip yeni versiyonlarını piyasaya sürmektedirler. Bu sayede güncel güvenlik önlemlerini atlatmada yeni yöntemler geliştirmektedirler. Son zamanlarda _Lumma_ _Stealer’in_ yeni ve gelişmiş bir sürümü de tespit edilmektedir.

![Lumma Çetesi ile Yapılan Röportajdan Kesit](/img/3.png)
_"Lumma'yı nasıl tanımlarsınız?"_

_“Şuan piyasadaki teknolojik olarak en gelişmiş bilgi çalan yazılımlardan biri. Teknoloji önce bizden çıkıyor sonra rakiplere geçiyor. Halihazırda birçok müşteriye sahip olmamıza rağmen ürünü sürekli geliştirmeye devam ediyoruz. Birçok kişi başarıya ulaştığında durup dinlenir. Biz ise asla durmuyoruz”_

# Lumma Stealer Ailesi

**LummaC2**, 2022 aralık ayından beri varlığını sürdürmekte olan Lumma zararlı yazılım ailesinin bir üyesidir. C/C++ yazılım diliyle geliştirilmiştir. Bu kötü amaçlı yazılım ailesinin Rus kökenli olduğu ve **“Shamel”** isimli tehdit aktörü tarafından geliştirildiği düşünülmektedir. LummaC2, aynı tehdit aktörü tarafından geliştirilen 2022 Ağustos ayından beri yeraltı forumlarında satılan LummaC’nin geliştirilmiş bir versiyonu olarak ortaya çıkmıştır. Tespit edilmesini zorlaştırmak için kapsamlı _obfuscation_ ve anti-analiz yöntemleri kullanılmaktadır.

Lumma Stealer, _darkweb_ forumlarında, kendi Telegram kanalında ve özel web sitesinde (lumma[.]shop) satışa sunulmaktadır. **MaaS (Malware as a Service)** modelini benimsemiş olan Lumma görece kolay erişimi ve kullanımı için teknik beceri gereksinimi olmaması sebebiyle hızla yayılmaktadır. Ayrıca satış paketlerinin en kapsamlısı alıcıların Lumma Stealer’ın kaynak koduna erişimine izin vermektedir. Bu sayede alıcıların da yazılımı özelleştirerek satmalarına ya da kullanmalarına olanak tanımaktadır.

![Lumma Web Sitesinde Yer Alan Fiyatlandırma](/img/4.png)

Lumma Stealer, hedef sistemden kripto para cüzdanları, tarayıcı bilgileri ve sistem verileri gibi hassas bilgileri çalmaktadır. Çaldığı bu verileri komut ve kontrol (C2) sunucusuyla iletişime geçerek iletmektedir. Öncelikle bağlantı kurabileceği sunucuya ulaşmaktadır. Daha sonra **POST** isteği göndermekte ve **User-Agent** bilgisi ve **“act=life”** parametresiyle kaydını yapmaktadır.

Daha sonra **Lumma** **ID** ve **“act=receive-message”** parametresiyle bir **POST** isteği daha gönderilmektedir. Çalmış olduğu verileri sıkıştırılmış bir dosya halinde tutmaktadır ve bu sıkıştırılmış dosyayı **“/api”** uzantılı bir C2 sunucusuna göndermektedir. Ancak Lumma Stealer’ın sürekli gelişen ve değişen yapısı sebebiyle son zamanlarda HTTPS protokolünü kullandığı görülmektedir. Bu sayede network trafiğinde tespit edilmesi zorlaşmaktadır.

![Lumma ID ile Gönderilen POST İsteği ve C2 İletişimi](/img/5.png)

## Yaygın Yayılma Yöntemleri

Lumma Stealer hedef sistemden özellikle tarayıcı bilgilerini, kripto para cüzdanlarını ve iki faktörlü doğrulama (2FA) verilerini de içeren hassas bilgileri çalmayı hedeflemektedir. Bu hedefine ulaşmak için ise başta phishing e-postaları olmak üzere çeşitli yayılma yöntemleri kullanmaktadır.

2024’ün Ekim ayında ortaya çıkan yöntemle saldırganlar sahte CAPTCHA sayfaları aracılığıyla hedef sisteme Lumma zararlısını yerleştirmektedirler. Bir diğer yöntem olarak ChatGPT veya VegasPro gibi popüler uygulamaların _crack’li_ versiyonlarıyla yayıldığı gözlemlenmektedir.

Lumma Stealer zararlısını yaymak için kullanılan bir diğer yöntem ise İçerik Dağıtım Ağları’dır (CDN - Content Delivery Network). Cloudflare CDN veya Discord CDN Lumma Stealer’in kullandığı CDN’lerden bazılarıdır. Ayrıca zararlının uzaktan kontrolünü sağlamak adına botlar oluşturmak için Discord API’leri kullanılmaktadır. Bu botlardan bazıları çalınan verileri özel Discord sunucularına veya kanallarına iletmek için geliştirilmektedir.

### Sahte CAPTCHA

![Sahte CAPTCHA Saldırı Zinciri](/img/6.png)

Saldırganlar Lumma Stealer zararlısını yaymak için sahte **CAPTCHA** doğrulama sayfaları oluşturmaktadır. Bu sayfalar sayesinde hedef sisteme bir Lumma Stealer yüklenmesini başlatan PowerShell komutu yürütülmektedir. Bu doğrulama sayfalarına çoğunlukla phishing tekniğiyle yönlendirme yapılmaktadır.

Doğrulama sayfası yüklendiğinde kullanıcıyı “insan olduğunu doğrula” sayfası karşılamaktadır. Sahte **bir “I’m not a robot”** butonu bulunmaktadır. Butona tıklandığında doğrulama için gerekli adımlar verilmektedir. **Run** komutu (Windows+R) çalıştırılıp yapıştırıldığında bir PowerShell komutu çalıştırılmaktadır ve zararlı dosya sisteme indirilmektedir.

![Sahte CAPTCHA Sayfası](/img/7.png)

Sahte CAPTCHA sayfasının kaynak kodu incelendiğinde **“document.execCommand("copy")”** komutu çalıştıran ve Base64’le şifrelenmiş bir PowerShell script’i içeren **“verify”** fonksiyonu bulunmaktadır. Bu komutla “I’m not a robot” butonuna tıklandığında, Base64 ile şifrelenmiş PowerShell komutu otomatik olarak panoya kopyalanmaktadır.

![Base64 ile Şifrelenmiş PowerShell Komutu](/img/8.png)

Base64 ile şifrelenmiş kısım _decode_ edildiğinde **mshta.exe** komutu olduğu ortaya çıkmaktadır. **Mshta.exe** **,** HTML uygulamalarını ve gömülü script’leri çalıştırmak için kullanılan meşru bir Windows aracıdır. Bu araç sayesinde verilen URL’de bulunan payload indirilmekte ve “INetCache” dizinine kaydedilmektedir

![Decode Edilen PowerShell Komutu](/img/9.png)

Bu komut satırında indirilen **“2ndhsoru”** dosyası, **dialer.exe** Windows aracı için hazırlanmış bir yürütülebilir (PE) dosyasıdır ve _overlay_ bölümünde bir script içermektedir. Bu script incelendiğinde _obfuscate_ edilmiş bir JavaScript dosyası olduğu görülmektedir.

Bu payload’da, **polyglot tekniği** kullanılmaktadır. Geçerli bir HTA içeriği, mshta tarafından çalıştırılabilen dosyaların içine gömülmektedir. Bu script JavaScript kodunu çalıştırmak için bir **‘eval’** fonksiyonu ile tetiklenmektedir.

JavaScript kodunun içerisinde AES ile şifrelenmiş bir PowerShell komutu bulunmaktadır. Bu komut ile içerisinde DLL’ler bulunan **K1.zip** dosyasını ve **Victirfree.exe** (Lumma Stealer) bulunan **K2.zip** dosyalarını **“C:\Users\%username%\AppData\Local\Temp”** dizinine indirip arşivden çıkarmaktadır.

![K1.zip ve K2.zip Dosyaları](/img/10.png)

Bir Lumma Stealer olan **Victirfree.exe** dosyası **process hollowing** tekniği için meşru **BitLockerToGo.exe** kullanmaktadır.

Zararlının enjekte olduğu **BitLockerToGo.exe**, bazı dosyaları **Temp** klasörüne kaydetmektedir. Bu dosyalardan **72RC2SM21DDZ2OAH3P30V1XPT5AE7YN.exe** isimli dosya **Killing.bat** ve **Voyuer.pif** dosyalarını aynı dizine kopyalamaktadır. Killing.bat dosyası, **wrsa.exe (Webroot Antivirus), opssvc.exe (Quick Heal Antivirus), bdservicehost.exe (Bitdefender)** gibi antivirüs işlemlerini kontrol etmek için **tasklist** ve **findstr** komutlarını kullanan _obfuscate_ edilmiş bir dosyadır.

![Process Hollowing Sonrası BitLockerToGo.exe Süreci](/img/11.png)

Lumma Stealer, kripto para cüzdanlarını, parolaları, tarayıcı bilgilerini ve diğer hassas verileri ele geçirmek için ilgili dosya dizinlerini hedef almaktadır. ***seed*.txt, *pass*.txt, *.kbdx, *ledger*.txt, *trezor*.txt, *metamask*.txt, bitcoin*.txt, *word*** ve ***wallet*.txt** gibi anahtar kelimeleri arayarak çalmak istediği bilgilere ulaşmak istemektedir.

![Tarayıcı Bilgilerinin Elde Edilmesi](/img/12.png)

Çalmış olduğu bilgileri Komuta kontrol (C2) sunucusuna göndermektedir. Lumma Stealer C2 sunucusu olarak çoğunlukla **“[.]shop”** üst düzey alan adına (TLD) sahip domain’ler kullanılmaktadır.

![C2 Sunucusu ile İletişime Geçilmesi][/img/13.png]

### Discord CDN

**Discord**, geniş ve çeşitli kullanıcı kitlesine sahip bir platformdur. Sadece oyunculara değil aynı zamanda içerik üreticilerine, yayıncılara ve farklı çevrimiçi topluluklara hitap etmektedir. Bu nedenle popüler olan bu platform siber saldırganlar için bir avlanma alanına dönüşmektedir. Üstelik saldırganlar para veya Discord Nitro gibi ödüllerle kişilerin güvenini kazanmaya çalışmaktadır. Lumma Stealer da bu şekilde Discord platformunu kullanmaktadır.

Saldırganlar genellikle rastgele açılmış veya ele geçirilmiş hesaplar kullanarak hedefledikleri kullanıcılara mesaj göndermektedirler. Hedefledikleri kullanıcıya para veya ‘nitro boost’ gibi ödüller karşılığında bir projede yardım etmelerini istemektedirler. Karşılığında istenen bu yardımın kısa ve kolay olduğunu belirterek hedeflenen kullanıcı ikna edilmektedir. Kullanıcı kabul ettiği takdirde bu proje dosyasını indirmesi istenmektedir.

![Örnek Yardım Mesajı](/img/14.png)

Bu sözde proje, Discord’un **CDN’si** üzerinden barındırılmaktadır (cdn[.]discordapp[.]com/attachments/). Dosyayı indirmek için gönderilen linke tıklanıldığında birden fazla kez indirme başlatılmaktadır. Lumma Stealer içeren zararlı dosya (4_iMagicInventory_1_2_s.exe) hedef sisteme indirilmektedir.

Dosya çalıştırıldığında “**gapi-node[.]io”** gibi zararlı bir domainle bağlantı kurmaya çalışmaktadır ve bu sayede kullanıcının kripto para cüzdanlarını ve tarayıcı verilerini çalmaktadır.

![Hedeflenen Kripto Para Cüzdanları](/img/15.png)

### Crack Yazılımlar

En eski yöntemlerden biri olan _crack’li_ yazılımlar, Lumma Stealer zararlı yazılımın yayılması için de kullanılmaktadır. Saldırganlar bir yükleyici’ye (loader’a) gizledikleri payload’larını bu şekilde hedef sisteme yerleştirmektedirler. Crack’li yazılımların kurulumu sırasında genellikle antivirüs araçlarının devre dışı bırakılması istenmektedir. Bu sayede kullanıcı Lumma Stealer için kendi eliyle alan tanımış olmaktadır.

![Crack Yazılım Saldırı Zinciri](/img/16.png)

Lumma Stealer, crack’li yazılımlarla hedef sistemlere yerleşmek için çoğunlukla YouTube videolarını kullanmaktadır. Ele geçirilmiş halihazırda crack’li yazılım içerikleri sunan YouTube kanallarında yazılımın kurulum rehberini sunmakta ve çoğunlukla **cuttly** ve **tinyurl** hizmetleriyle kısaltılmış URL’ler içermektedir.

![Ele Geçirilmiş YouTube Hesapları](/img/17.png)

Web filtrelerini atlatmak için GitHub ve MediaFire gibi açık kaynak kodlu platformları kullanarak Lumma Stealer’ı yüklemekle görevli .NET yükleyicisine (loader) erişim sağlamaktadır.

Linklerde bulunan ZIP dosyalarının belirli aralıklarla güncellendiği tespit edilmiştir. Bu şekilde en güncel Lumma Stealer’ın yayılmaya devam etmekte olduğu görülmektedir.

![MediaFire Üzerinden İndirilen Lumma Stealer](/img/18.png)

Bu örnekte görülen **“installer_Full_Version_V.1f2.zip”** isimli dosya bir PowerShell komutu çalıştıran **LNK** dosyası içermektedir. Bu PowerShell komutu **John1323456** kullanıcısına ait **"New"** adlı GitHub reposu üzerinden bir .NET çalıştırılabilir dosyasını indirmektedir.

![Lumma Stealer Barındıran GitHub Reposu](/img/19.png)

Örnekte ulaşılan **Installer-Install-2023_v0y.6.6.exe** incelendiğinde _obfuscate_ edilmiş olduğu görülmektedir. Zararlı yazılım sistem kontrolü yapmaktadır bu sayede izole sistemlerde çalışmamaktadır.

Bulaştığı sistemde fark edilmeden yürütülmesini sağlamak için **ProcessStartInfo** nesnesinin bazı özelliklerini kullanmaktadır. **RedirectStandardInput**, **CreateNoWindow**, **UseShellExecute** kullanarak çalışan komutların ve programların arka planda çalışmasını ve antivirüs uygulamalarından kaçınmayı sağlamaktadır.

![processStartInfo Özelliklerinin Ayarlanması](/img/20.png)

Bu zararlı Base64 ile şifrelenmiş dört farklı sunucuyu içeren IP adreslerini barındırmaktadır. Mevcut sistem tarihine bağlı olarak binary verisini çekmek için uygun olan IP adresini seçmektedir.

Bu sunuculardan biri olan **176[.]113[.]115[.]224:29983** sunucusuyla bir iletişime geçmektedir ve istediği veriyi indirmektedir. Sunucudan indirmiş olduğu AES şifreli script’in şifresini çözmekte ve sisteme bir DLL dosyası yerleştirmektedir.

Bu örnekte indirilmiş olan **Agacantwhitey.dll** dosyası tespitten kaçınmak için şifrelenmiş bir yapıdadır. Ayrıca anti-vm ve anti-debug korumasını sağlamak adına birçok öğeyi kontrol etmektedir. Bunlardan bazıları aşağıda verilmiştir.

* Aktif pencerenin kontrol edilmesi: GetForegroundWindow ile sistemde aşağıda belirtilen debugger’ların çalışıp çalışmadığı kontrol etmektedir.

	"x32dbg," "x64dbg," "windbg," "ollydbg," "dnspy," "immunity debugger," "hyperdbg," "debug," "debugger," "cheat engine," "cheatengine," "ida."

* Antivirüs ve Sandbox kontrolünün yapılması:

	SbieDll.dll (Sandboxie), cmdvrt64.dll (Comodo Antivirus), cuckoomon.dll (Cuckoo Sandbox), SxIn.dll (360 Total Security)

	Johnson, Miller, malware, maltest, CurrentUser, Sandbox, virus, John Doe, test user, sand box, ve WDAGUtilityAccount gibi kullanıcı adlarının kontrol edilmektedir.

* Sanal makine kullanımının kontrol edilmesi: WMI sorgusu ile bilgisayar sistemini kontrol etmektedir.

	"innotek gmbh" (VirtualBox ile ilişkili), "microsoft corporation" (Hyper-V ile ilişkilendirilen) gibi üretici isimleri ve "VirtualBox", "vmware." Gibi model isimleri kontrol edilmektedir.

	Ayrıca, “C:\Program Files\VMware” ve “C:\Program Files\oracle\virtualbox guest additions” dizinlerinin varlığı kontrol edilmektedir.

* Sistem servislerinin ve process isimlerinin kontrol edilmesi:

	"vmbus," "VMBusHID," ve "hyperkbd" servislerinin varlığı incelenmektedir.

	"vboxservice," "VGAuthService," "vmusrvc," ve "qemu-ga" process’lerinin varlığı kontrol edilmektedir

# Yeni LummaC2 Versiyonu 

Son zamanlarda _Lumma_ _Stealer’in_ yeni ve gelişmiş bir sürümü tespit edilmiştir. _Lumma Stealer’in_ yeni sürümünde tespitten kaçınmak amacıyla gelişmiş **kod akışı karmaşıklaştırma (code flow obfuscation)**, **API hash çözümleme (API hash resolving), Heaven’s Gate, ETWTi callback’lerini devre dışı bırakma, anti-sandbox** teknikleri gibi teknikler kullandığı gözlenmektedir.

![Lumma Stealer Yeni Versiyonu Saldırı Zinciri](/img/21.png)

_Lumma Stealer’in_ yeni sürümünü kullanan bir tehdit aktörünün _Lumma’yı_ dağıtmak amacıyla **karmaşıklaştırılmış (obfuscated) PowerShell** **script’leri** kullandığı tespit edilmektedir. Bu _script_, **Base64** ile şifrelenmiş **Lumma** **payload’ı** ve **GOO.dll** isimli **.NET** tabanlı yükleyici (loader) olmak üzere iki dosya içermektedir.

_PowerShell_ _script’i_ **Reflection** **API** kullanarak GOO.dll isimli .NET çalıştırılabilir dosyasının yüklemektedir. .NET çalıştırılabilir dosyasının **Crypto** **Obfuscator** ile karmaşıklaştırıldığı (obfuscation) görülmektedir. Daha sonra GOO.dll dosyası, _Lumma_ _payload’ının_ meşru olan **RegSvcs.exe** sürecine (process) enjekte etmektedir. Bu sayede _Lumma payload’ı_ çalışırken meşru bir süreç olan **RegSvcs.exe** gibi görünmektedir. Bu sayede zararlı aktivitelerini tespit edilmeden gerçekleştirip hassas verileri çalmayı amaçladığı görülmektedir.

Şifrelenmiş yapıdaki **Lumma ikili dosyası (binary file)** incelendiğinde **Process Environment Block (PEB)** ve özel API hash tabloları kullanılarak **LoadLibrary** ve **GetProcAddress** gibi davranışsal tespit sistemleri tarafından sıklıkla işaretlenen işlevlere çağrı (call) yapmaktan kaçındığı görülmektedir.

Kod blokları arasındaki mantıksal bağlantılar çalışma zamanında dinamik olarak hesaplanmakta, bu da kod akışını bozarak statik analiz ve _decompiler_ araçlarının kodu anlaması zorlaşmaktadır. Yapılan bu hesaplama işlemi de her basamakta değişmektedir. Bu karmaşıklaştırma (obfuscation) tekniği tüm koda yayılmış durumdadır. **Kod Akışı Karmaşıklaştırma (Code Flow Obfuscation)** tekniği olarak bilinen bu teknik programın kontrol akışını kasıtlı olarak değiştirerek tersine mühendislik analizlerini zorlaştırmayı amaçlamaktadır.

Lumma bu yeni sürümde kullanacağı **RtlAllocateHeap**, **RtlReAllocateHeap**, **RtlFreeHeap**, **RtlExpandEnvironmenttrings** gibi API’leri gizlemek için **hash** değerlerini kullanmaktadır. Dinamik olarak bu hash değerlerini çözümlemekte ve dilediği API’yi çağırmaktadır (call). Bu tekniğe **API Hash Çözümleme (API Hash Resolving)** tekniği denmektedir. **C&C** sunucularıyla iletişime geçmek için kullanacağı API’leri de bu tekniği kullanarak çözümlemektedir.

**32-bit** olarak derlenmiş olan _Lumma_ _Stealer’in_ yeni sürümü **64-bit** sistemlerde de çalışarak **Heaven’s** **Gate** tekniğini kullanmaktadır. Bulaştığı sistemin nasıl bir sistem olduğunu kontrol etmekte ve ona uyumlu çağrıları yapmaktadır.

Ayrıca Lumma yeni versiyonunda modern uç nokta tespit (EDR) ürünleri tarafından yapılan müdahaleleri en aza indirmek amacıyla temiz ve hook’lanmamış sistem çağrıları (syscall) gerçekleştirmek için **ntdll.dll** kütüphanesini **yeniden eşlemektedir (remap).**

![ntdll.dll Kütüphanesinin Yeniden Eşlenmesi](/img/22.png)

Bulaştığı sistemin 32-bit veya 64-bit olduğunu kontrol ettikten sonra uygun DLL sürümü belirlenmektedir. Uygun ntdll.dll dosyasını yeniden eşlemek (remap) için **syscall** çağrılarını kullanmaktadır. Kullanacağı syscall çağrıları da hash değerleri olarak bulunduğu için hash çözümleme yapılmaktadır. Bu sayede kodun analizini zorlaştırmak amaçlanmaktadır.

_Lumma_ _Stealer_, gerçekleştirdiği bu sistem çağrılarının güvenlik yazılımları tarafından tespit edilmemesi için **ETW** **(Event Tracing for Windows) callback’lerini** kaldırmaktadır. **EWT callback’leri**, Windows’un işlemler ve olaylar hakkında güvenlik sistemlerine erkenden bilgi vermek için tetiklediği izleme fonksiyonlarıdır. Bunların devre dışıı bırakılması Lumma zararlısının tespit edilmesini engellemektedir.

_Lumma_, bilinen _sandbox’larla_, antivirüs DLL’leriyle ve sanal makinelerle ilişkili _artifact’lere_ yönelik _hardcoded_ _hash_ değerlerini kullanarak kontroller gerçekleştirmektedir. Sanallaştırılmış bir ortamda bulunuyorsa zararlı işlemlerini gerçekleştirmemektedir.

Ayrıca bulaştığı sistemin dilini kontrol etmektedir. **Kullanıcı** **varsayılan** **dili** olarak **Rusça** kullanılıyorsa kötü amaçlı işlemlerini gerçekleştirmemektedir.

_Lumma_ _Stealer_, iletişim kuracağı C2 sunucularının _domain’lerini_ şifreli bir şekilde tutmaktadır. Sırayla bu domain’lerin şifresini çözerek **POST** isteği ile bağlantı kurmaya çalışmaktadır.

![C&C Sunucusuna Yapılan Bağlantı Denemeleri](/img/23.png)

Eğer bu C2 sunucularından olumlu yanıt gelmezse C2 sunucusuyla iletişim için **Steam** kullanıcı URL’lerini kullanmaktadır. _Steam_ kullanıcı adları şifreli olarak URL içerisinde yer almaktadır. Şifresi çözülen kullanıcı adları kullanılarak C2 sunucusuyla iletişime geçilmektedir.

İletişim kurduktan sonra C2 adresinden hedef alınacak verileri belirten şifrelenmiş bir **yapılandırma** **dosyası** alınmaktadır. Bu dosya, **web tarayıcıları, kripto cüzdanları, parola yöneticileri, VPN istemcileri, FTP uygulamaları** ve **Telegram, Discord** gibi mesajlaşma uygulamalarını içermektedir.

Veri sızdırma (exfiltration) süreci otomatik olarak gerçekleşmektedir. Bulaşılan sistemde yaklaşık olarak 90 tane uygulama ve kritik dosya yolları hedef alınmaktadır. Kripto Para Cüzdanları, e-posta uygulamaları gibi verileri de hedeflemektedir.

# Sonuç

_Lumma_ _Stealer_, siber tehdit aktörleri tarafından sürekli olarak evrimleşen ve gelişen sofistike bir bilgi hırsızı (info stealer) yazılımdır. Bu kötü amaçlı yazılım, gelişmiş kaçınma teknikleri ve sürekli gelişen yöntemleri sayesinde geleneksel güvenlik önlemlerini aşmayı amaçlamaktadır. Lumma gibi stealer zararlı yazılımlarının sürekli gelişerek saldırılarına devam etmesi kurumlar için önemli bir tehdit oluşturmaktadır. Kurumların bu gelişmiş tehditlere karşı önlem olarak proaktif bir savunma gerçekleştirmeli ve daha güçlü uç nokta (endpoint) koruma önlemleri sağlamaları gerekmektedirler.