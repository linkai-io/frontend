package parsers

var SpecialCaseTLDs = map[string]struct{}{
	"shopify.com":               struct{}{},
	"amazonaws.com":             struct{}{},
	"elasticbeanstalk.com":      struct{}{},
	"cloudfront.net":            struct{}{},
	"dyndns.org":                struct{}{},
	"cdn77.org":                 struct{}{},
	"cdn77-ssl.net":             struct{}{},
	"cdn77.net":                 struct{}{},
	"cdn77-secure.org":          struct{}{},
	"cloudns.asia":              struct{}{},
	"cloudns.biz":               struct{}{},
	"cloudns.club":              struct{}{},
	"cloudns.cc":                struct{}{},
	"cloudns.eu":                struct{}{},
	"cloudns.in":                struct{}{},
	"cloudns.info":              struct{}{},
	"cloudns.org":               struct{}{},
	"cloudns.pro":               struct{}{},
	"cloudns.pw":                struct{}{},
	"cloudns.us":                struct{}{},
	"dyn.cosidns.de":            struct{}{},
	"dynamisches-dns.de":        struct{}{},
	"dnsupdater.de":             struct{}{},
	"internet-dns.de":           struct{}{},
	"l-o-g-i-n.de":              struct{}{},
	"dynamic-dns.info":          struct{}{},
	"feste-ip.net":              struct{}{},
	"knx-server.net":            struct{}{},
	"static-access.net":         struct{}{},
	"dreamhosters.com":          struct{}{},
	"dy.fi":                     struct{}{},
	"dyndns-at-home.com":        struct{}{},
	"dyndns-at-work.com":        struct{}{},
	"dyndns-blog.com":           struct{}{},
	"dyndns-free.com":           struct{}{},
	"dyndns-home.com":           struct{}{},
	"dyndns-ip.com":             struct{}{},
	"dyndns-mail.com":           struct{}{},
	"dyndns-office.com":         struct{}{},
	"dyndns-pics.com":           struct{}{},
	"dyndns-remote.com":         struct{}{},
	"dyndns-server.com":         struct{}{},
	"dyndns-web.com":            struct{}{},
	"dyndns-wiki.com":           struct{}{},
	"dyndns-work.com":           struct{}{},
	"dyndns.biz":                struct{}{},
	"dyndns.info":               struct{}{},
	"dyndns.tv":                 struct{}{},
	"at-band-camp.net":          struct{}{},
	"ath.cx":                    struct{}{},
	"barrel-of-knowledge.info":  struct{}{},
	"barrell-of-knowledge.info": struct{}{},
	"better-than.tv":            struct{}{},
	"blogdns.com":               struct{}{},
	"blogdns.net":               struct{}{},
	"blogdns.org":               struct{}{},
	"blogsite.org":              struct{}{},
	"boldlygoingnowhere.org":    struct{}{},
	"broke-it.net":              struct{}{},
	"buyshouses.net":            struct{}{},
	"cechire.com":               struct{}{},
	"dnsalias.com":              struct{}{},
	"dnsalias.net":              struct{}{},
	"dnsalias.org":              struct{}{},
	"dnsdojo.com":               struct{}{},
	"dnsdojo.net":               struct{}{},
	"dnsdojo.org":               struct{}{},
	"does-it.net":               struct{}{},
	"doesntexist.com":           struct{}{},
	"doesntexist.org":           struct{}{},
	"dontexist.com":             struct{}{},
	"dontexist.net":             struct{}{},
	"dontexist.org":             struct{}{},
	"doomdns.com":               struct{}{},
	"doomdns.org":               struct{}{},
	"dvrdns.org":                struct{}{},
	"dyn-o-saur.com":            struct{}{},
	"dynalias.com":              struct{}{},
	"dynalias.net":              struct{}{},
	"dynalias.org":              struct{}{},
	"dynathome.net":             struct{}{},
	"dyndns.ws":                 struct{}{},
	"endofinternet.net":         struct{}{},
	"endofinternet.org":         struct{}{},
	"endoftheinternet.org":      struct{}{},
	"est-a-la-maison.com":       struct{}{},
	"est-a-la-masion.com":       struct{}{},
	"est-le-patron.com":         struct{}{},
	"est-mon-blogueur.com":      struct{}{},
	"for-better.biz":            struct{}{},
	"for-more.biz":              struct{}{},
	"for-our.info":              struct{}{},
	"for-some.biz":              struct{}{},
	"for-the.biz":               struct{}{},
	"forgot.her.name":           struct{}{},
	"forgot.his.name":           struct{}{},
	"from-ak.com":               struct{}{},
	"from-al.com":               struct{}{},
	"from-ar.com":               struct{}{},
	"from-az.net":               struct{}{},
	"from-ca.com":               struct{}{},
	"from-co.net":               struct{}{},
	"from-ct.com":               struct{}{},
	"from-dc.com":               struct{}{},
	"from-de.com":               struct{}{},
	"from-fl.com":               struct{}{},
	"from-ga.com":               struct{}{},
	"from-hi.com":               struct{}{},
	"from-ia.com":               struct{}{},
	"from-id.com":               struct{}{},
	"from-il.com":               struct{}{},
	"from-in.com":               struct{}{},
	"from-ks.com":               struct{}{},
	"from-ky.com":               struct{}{},
	"from-la.net":               struct{}{},
	"from-ma.com":               struct{}{},
	"from-md.com":               struct{}{},
	"from-me.org":               struct{}{},
	"from-mi.com":               struct{}{},
	"from-mn.com":               struct{}{},
	"from-mo.com":               struct{}{},
	"from-ms.com":               struct{}{},
	"from-mt.com":               struct{}{},
	"from-nc.com":               struct{}{},
	"from-nd.com":               struct{}{},
	"from-ne.com":               struct{}{},
	"from-nh.com":               struct{}{},
	"from-nj.com":               struct{}{},
	"from-nm.com":               struct{}{},
	"from-nv.com":               struct{}{},
	"from-ny.net":               struct{}{},
	"from-oh.com":               struct{}{},
	"from-ok.com":               struct{}{},
	"from-or.com":               struct{}{},
	"from-pa.com":               struct{}{},
	"from-pr.com":               struct{}{},
	"from-ri.com":               struct{}{},
	"from-sc.com":               struct{}{},
	"from-sd.com":               struct{}{},
	"from-tn.com":               struct{}{},
	"from-tx.com":               struct{}{},
	"from-ut.com":               struct{}{},
	"from-va.com":               struct{}{},
	"from-vt.com":               struct{}{},
	"from-wa.com":               struct{}{},
	"from-wi.com":               struct{}{},
	"from-wv.com":               struct{}{},
	"from-wy.com":               struct{}{},
	"ftpaccess.cc":              struct{}{},
	"fuettertdasnetz.de":        struct{}{},
	"game-host.org":             struct{}{},
	"game-server.cc":            struct{}{},
	"getmyip.com":               struct{}{},
	"gets-it.net":               struct{}{},
	"gotdns.com":                struct{}{},
	"gotdns.org":                struct{}{},
	"groks-the.info":            struct{}{},
	"groks-this.info":           struct{}{},
	"ham-radio-op.net":          struct{}{},
	"here-for-more.info":        struct{}{},
	"hobby-site.com":            struct{}{},
	"hobby-site.org":            struct{}{},
	"home.dyndns.org":           struct{}{},
	"homedns.org":               struct{}{},
	"homeftp.net":               struct{}{},
	"homeftp.org":               struct{}{},
	"homeip.net":                struct{}{},
	"homelinux.com":             struct{}{},
	"homelinux.net":             struct{}{},
	"homelinux.org":             struct{}{},
	"homeunix.com":              struct{}{},
	"homeunix.net":              struct{}{},
	"homeunix.org":              struct{}{},
	"iamallama.com":             struct{}{},
	"in-the-band.net":           struct{}{},
	"is-a-anarchist.com":        struct{}{},
	"is-a-blogger.com":          struct{}{},
	"is-a-bookkeeper.com":       struct{}{},
	"is-a-bruinsfan.org":        struct{}{},
	"is-a-bulls-fan.com":        struct{}{},
	"is-a-candidate.org":        struct{}{},
	"is-a-caterer.com":          struct{}{},
	"is-a-celticsfan.org":       struct{}{},
	"is-a-chef.com":             struct{}{},
	"is-a-chef.net":             struct{}{},
	"is-a-chef.org":             struct{}{},
	"is-a-conservative.com":     struct{}{},
	"is-a-cpa.com":              struct{}{},
	"is-a-cubicle-slave.com":    struct{}{},
	"is-a-democrat.com":         struct{}{},
	"is-a-designer.com":         struct{}{},
	"is-a-doctor.com":           struct{}{},
	"is-a-financialadvisor.com": struct{}{},
	"is-a-geek.com":             struct{}{},
	"is-a-geek.net":             struct{}{},
	"is-a-geek.org":             struct{}{},
	"is-a-green.com":            struct{}{},
	"is-a-guru.com":             struct{}{},
	"is-a-hard-worker.com":      struct{}{},
	"is-a-hunter.com":           struct{}{},
	"is-a-knight.org":           struct{}{},
	"is-a-landscaper.com":       struct{}{},
	"is-a-lawyer.com":           struct{}{},
	"is-a-liberal.com":          struct{}{},
	"is-a-libertarian.com":      struct{}{},
	"is-a-linux-user.org":       struct{}{},
	"is-a-llama.com":            struct{}{},
	"is-a-musician.com":         struct{}{},
	"is-a-nascarfan.com":        struct{}{},
	"is-a-nurse.com":            struct{}{},
	"is-a-painter.com":          struct{}{},
	"is-a-patsfan.org":          struct{}{},
	"is-a-personaltrainer.com":  struct{}{},
	"is-a-photographer.com":     struct{}{},
	"is-a-player.com":           struct{}{},
	"is-a-republican.com":       struct{}{},
	"is-a-rockstar.com":         struct{}{},
	"is-a-socialist.com":        struct{}{},
	"is-a-soxfan.org":           struct{}{},
	"is-a-student.com":          struct{}{},
	"is-a-teacher.com":          struct{}{},
	"is-a-techie.com":           struct{}{},
	"is-a-therapist.com":        struct{}{},
	"is-an-accountant.com":      struct{}{},
	"is-an-actor.com":           struct{}{},
	"is-an-actress.com":         struct{}{},
	"is-an-anarchist.com":       struct{}{},
	"is-an-artist.com":          struct{}{},
	"is-an-engineer.com":        struct{}{},
	"is-an-entertainer.com":     struct{}{},
	"is-by.us":                  struct{}{},
	"is-certified.com":          struct{}{},
	"is-found.org":              struct{}{},
	"is-gone.com":               struct{}{},
	"is-into-anime.com":         struct{}{},
	"is-into-cars.com":          struct{}{},
	"is-into-cartoons.com":      struct{}{},
	"is-into-games.com":         struct{}{},
	"is-leet.com":               struct{}{},
	"is-lost.org":               struct{}{},
	"is-not-certified.com":      struct{}{},
	"is-saved.org":              struct{}{},
	"is-slick.com":              struct{}{},
	"is-uberleet.com":           struct{}{},
	"is-very-bad.org":           struct{}{},
	"is-very-evil.org":          struct{}{},
	"is-very-good.org":          struct{}{},
	"is-very-nice.org":          struct{}{},
	"is-very-sweet.org":         struct{}{},
	"is-with-theband.com":       struct{}{},
	"isa-geek.com":              struct{}{},
	"isa-geek.net":              struct{}{},
	"isa-geek.org":              struct{}{},
	"isa-hockeynut.com":         struct{}{},
	"issmarterthanyou.com":      struct{}{},
	"isteingeek.de":             struct{}{},
	"istmein.de":                struct{}{},
	"kicks-ass.net":             struct{}{},
	"kicks-ass.org":             struct{}{},
	"knowsitall.info":           struct{}{},
	"land-4-sale.us":            struct{}{},
	"lebtimnetz.de":             struct{}{},
	"leitungsen.de":             struct{}{},
	"likes-pie.com":             struct{}{},
	"likescandy.com":            struct{}{},
	"merseine.nu":               struct{}{},
	"mine.nu":                   struct{}{},
	"misconfused.org":           struct{}{},
	"mypets.ws":                 struct{}{},
	"myphotos.cc":               struct{}{},
	"neat-url.com":              struct{}{},
	"office-on-the.net":         struct{}{},
	"on-the-web.tv":             struct{}{},
	"podzone.net":               struct{}{},
	"podzone.org":               struct{}{},
	"readmyblog.org":            struct{}{},
	"saves-the-whales.com":      struct{}{},
	"scrapper-site.net":         struct{}{},
	"scrapping.cc":              struct{}{},
	"selfip.biz":                struct{}{},
	"selfip.com":                struct{}{},
	"selfip.info":               struct{}{},
	"selfip.net":                struct{}{},
	"selfip.org":                struct{}{},
	"sells-for-less.com":        struct{}{},
	"sells-for-u.com":           struct{}{},
	"sells-it.net":              struct{}{},
	"sellsyourhome.org":         struct{}{},
	"servebbs.com":              struct{}{},
	"servebbs.net":              struct{}{},
	"servebbs.org":              struct{}{},
	"serveftp.net":              struct{}{},
	"serveftp.org":              struct{}{},
	"servegame.org":             struct{}{},
	"shacknet.nu":               struct{}{},
	"simple-url.com":            struct{}{},
	"space-to-rent.com":         struct{}{},
	"stuff-4-sale.org":          struct{}{},
	"stuff-4-sale.us":           struct{}{},
	"teaches-yoga.com":          struct{}{},
	"thruhere.net":              struct{}{},
	"traeumtgerade.de":          struct{}{},
	"webhop.biz":                struct{}{},
	"webhop.info":               struct{}{},
	"webhop.net":                struct{}{},
	"webhop.org":                struct{}{},
	"worse-than.tv":             struct{}{},
	"writesthisblog.com":        struct{}{},
	"evennode.com":              struct{}{},
	"fbsbx.com":                 struct{}{},
	"fastlylb.net":              struct{}{},
	"fastly.net":                struct{}{},
	"firebaseapp.com":           struct{}{},
	"github.io":                 struct{}{},
	"githubusercontent.com":     struct{}{},
	"gitlab.io":                 struct{}{},
	"appspot.com":               struct{}{},
	"cloudfunctions.net":        struct{}{},
	"cloud.goog":                struct{}{},
	"codespot.com":              struct{}{},
	"googleapis.com":            struct{}{},
	"googlecode.com":            struct{}{},
	"pagespeedmobilizer.com":    struct{}{},
	"publishproxy.com":          struct{}{},
	"withgoogle.com":            struct{}{},
	"withyoutube.com":           struct{}{},
	"herokuapp.com":             struct{}{},
	"herokussl.com":             struct{}{},
	"azurecontainer.io":         struct{}{},
	"azurewebsites.net":         struct{}{},
	"azure-mobile.net":          struct{}{},
	"cloudapp.net":              struct{}{},
	"netlify.com":               struct{}{},
}