# TCP-Syn-Flood-Defense

Ilk grup asagida detayları verilen nitelikte bir tcp syn flood saldirisi yapabilen bir kod gelistirecek.  Diğer grup ise OS kernel uzerinde duzenleme yapma yetkinizin olmadigi bir sunucu uzerinde gelistirdikleri kod ile bu saldiriyi engellemeye ve loglamaya calisacaklar. Engelleme tarafinda engine olarak kernel’in netfilter modulunu kullanabilirsiniz, veya iptables’in direct kendisine rule ekleyebilirsiniz. Kod’ları kendisinizi rahat hissettiginiz bir programlama dili ile yazabilirsiniz.  Python ve Java uygun,  Bash/Shell kabul edilmiyor,  C ile yazılırsa ekstra guzel olur.




1.Grup:

Arguman olarak host ip ve port bilgisini kullanıcıdan alacak. Interface name bilgisi static olarak scripte yazılabilecek, opsiyonel olarak sistemin kendisinden otomatik olarak alabilir veya bir conf dosyasından okuyabilir.
Syn flood yapilacak source host IP’sini 1,254 arasinda random uretecek bir class yazılarak,  source port bilgisini de random ureterek tcp flag olarak S (Syn) her pakete ekleyecek. Toplam gonderdigi paket
Sayısını ekrana basacak.


2.Grup

Aynı ip’den 3 saniye icerisinde 50’den fazla gonderilen Syn paketlerini tespit edecek,  bu malicious ip adreslerini Tcp RST ile reject edecek, loglayacak veya stdout’a basacak. 1 dakika sonra tum engelledigi IP’adreslerini tekrar white liste tasiyacak, saldirinin devam etmesi halinde sonsuza kadar blackliste ekleyecek bir dosyaya engelledigi IP adreslerini loglayacak.
