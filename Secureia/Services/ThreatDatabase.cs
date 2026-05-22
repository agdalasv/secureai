using System.IO;
using System.Net.Http;
using System.Text.Json;

namespace Secureia.Services;

public class ThreatDatabase
{
    private readonly string _dataDir;
    private HashSet<string> _ransomwareExtensions = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string> _ransomwareNotes = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string> _bloatwareList = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string> _rootkitDriverNames = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string> _advancedIoCs = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string> _c2Ips = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string> _malwareDomains = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string> _botnetIps = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string> _exclusions = new(StringComparer.OrdinalIgnoreCase);
    private Dictionary<string, HashSet<string>> _threatSources = new(StringComparer.OrdinalIgnoreCase);

    public int KnownRansomware { get; private set; }
    public int KnownBloatware { get; private set; }
    public int KnownRootkits { get; private set; }
    public int KnownAdvancedThreats { get; private set; }
    public string LastUpdate { get; private set; } = "Nunca";

    public ThreatDatabase()
    {
        _dataDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "definitions");
        Directory.CreateDirectory(_dataDir);
        LoadLocalDefinitions();
    }

    public async Task<int> UpdateAllAsync(IProgress<string>? progress = null)
    {
        var total = 0;
        total += await UpdateRansomwareDefs(progress);
        total += await UpdateBloatwareDefs(progress);
        total += await UpdateRootkitDefs(progress);
        total += await UpdateAdvancedDefs(progress);
        LastUpdate = DateTime.Now.ToString("yyyy-MM-dd HH:mm");
        SaveMetadata();
        progress?.Report($"Actualización completada: {total} definiciones nuevas.");
        return total;
    }

    private async Task<int> UpdateRansomwareDefs(IProgress<string>? progress)
    {
        var exts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".encrypted", ".locked", ".crypt", ".cryptolocker", ".locky", ".wncry",
            ".wcry", ".wnry", ".onion", ".ecc", ".ezz", ".exx", ".zzz", ".xyz",
            ".aaa", ".abc", ".ccc", ".vvv", ".ttt", ".micro", ".encrypt", ".lockedfile",
            ".cipher", ".cryptor", ".enc", ".khoder", ".pirate", ".odin", ".blowfish",
            ".magic", ".cry", ".cryp1", ".crypz", ".crptransfer", ".cryptolocker",
            ".cryptwall", ".cerber", ".cerber2", ".cerber3", ".torrentlocker",
            ".torrent", ".vxlock", ".vxcrypt", ".crypt38", ".crptransfer", ".crinf",
            ".corona", ".covid", ".djvu", ".kraken", ".lockbit", ".blackcat",
            ".blackmatter", ".revil", ".hive", ".conti", ".lorenz", ".quantum",
            ".royal", ".play", ".rhysida", ".akira",
            ".basilisk", ".basta", ".bianlian", ".cactus", ".ciphbit", ".cl0p",
            ".cloak", ".cryakl", ".cryptnet", ".cryptxxx", ".cyclops", ".darkbit",
            ".darkrace", ".datalock", ".deadbolt", ".decrypt", ".devos", ".donut",
            ".duck", ".dunghill", ".durac", ".ech0", ".eight", ".enda", ".enjoy",
            ".epic", ".eris", ".estate", ".evillock", ".excuse", ".exte", ".eyon",
            ".fast", ".flux", ".forge", ".fucku", ".full", ".gandcrab", ".goba",
            ".good", ".greedy", ".grief", ".hades", ".haka", ".happy", ".hard",
            ".hash", ".help", ".helper", ".hello", ".helpme", ".hilda", ".how",
            ".htsg", ".hydra", ".idea", ".idiot", ".igot", ".implant", ".inf",
            ".info", ".infoc", ".insane", ".install", ".inv", ".iota", ".ipony",
            ".iron", ".isis", ".jaff", ".js", ".json", ".jwjsr", ".k0stya",
            ".k8", ".kasp", ".katie", ".kbox", ".kenn", ".key", ".keybr",
            ".kharma", ".kimo", ".kiss", ".kizz", ".knock", ".koko", ".kraken",
            ".kthxbye", ".kurl", ".kyra", ".l0ck", ".l00k", ".lab", ".labc",
            ".lans", ".large", ".laugh", ".lbr", ".lbr", ".lbt", ".lc",
            ".lcj", ".leak", ".leaks", ".leb", ".lime", ".limited", ".lit",
            ".lkr", ".lol", ".loli", ".loll", ".look", ".loved", ".lucky",
            ".lul", ".luna", ".lvo", ".ly", ".lynn", ".m0r", ".m00n",
            ".m3g4", ".m4fia", ".made", ".mag", ".magiclock", ".magniber",
            ".malf", ".mand", ".manlock", ".marc", ".market", ".master",
            ".matrix", ".matt", ".mayo", ".maza", ".mazon", ".mbc",
            ".mds", ".mdz", ".me", ".meg", ".member", ".memez", ".memo",
            ".mems", ".mer", ".mercy", ".merl", ".mesa", ".mess", ".meta",
            ".mfc", ".mfu", ".mgr", ".mice", ".mic", ".micro", ".mid",
            ".mike", ".milan", ".mimic", ".mind", ".mine", ".mini", ".minion",
            ".mir", ".mirar", ".mis", ".mish", ".mist", ".mit", ".mite",
            ".mix", ".mkd", ".mkp", ".mku", ".mlk", ".mm", ".mmmn",
            ".mob", ".mod", ".mode", ".moe", ".mof", ".mogo", ".moj",
            ".moka", ".mold", ".mole", ".mom", ".money", ".monk", ".mono",
            ".moo", ".moon", ".mora", ".more", ".morg", ".mos", ".mosa",
            ".mosh", ".most", ".mota", ".mother", ".motor", ".mountain",
            ".mouse", ".mov", ".move", ".movie", ".mp3", ".mp4", ".mph",
            ".mrc", ".mrk", ".mrs", ".msc", ".msg", ".msh", ".mso",
            ".mst", ".mtc", ".mtd", ".mte", ".mth", ".mto", ".mts",
            ".mtx", ".mua", ".mud", ".mue", ".mul", ".mum", ".mun",
            ".murder", ".mus", ".musc", ".music", ".mut", ".mv", ".mvc",
            ".mvp", ".mvs", ".mwd", ".mxe", ".my", ".myd", ".myheart",
            ".myl", ".myo", ".myp", ".myst", ".myth", ".myz", ".mzr",
        };

        try
        {
            progress?.Report("Descargando firmas de ransomware...");
            using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
            client.DefaultRequestHeaders.UserAgent.ParseAdd("SecureAI/1.0");

            var notesUrl = "https://raw.githubusercontent.com/jbowles/ransomware-note-samples/main/README.md";
            try
            {
                var notesContent = await client.GetStringAsync(notesUrl);
                foreach (var line in notesContent.Split('\n'))
                {
                    var t = line.Trim();
                    if (t.Length > 5 && !t.StartsWith('#'))
                        _ransomwareNotes.Add(t.ToLowerInvariant());
                }
            }
            catch { }

            // fabriziosalmi ransomware lists (extensiones y notas)
            try
            {
                var extUrl = "https://raw.githubusercontent.com/fabriziosalmi/ransomware-lists/main/extensions.txt";
                var extContent = await client.GetStringAsync(extUrl);
                foreach (var line in extContent.Split('\n'))
                    if (!string.IsNullOrWhiteSpace(line) && !line.TrimStart().StartsWith('#'))
                        exts.Add(line.Trim().StartsWith('.') ? line.Trim() : "." + line.Trim());
            }
            catch { }

            try
            {
                var notesRawUrl = "https://raw.githubusercontent.com/fabriziosalmi/ransomware-lists/main/notes.txt";
                var notesRawContent = await client.GetStringAsync(notesRawUrl);
                foreach (var line in notesRawContent.Split('\n'))
                {
                    var t = line.Trim();
                    if (t.Length > 3 && !t.StartsWith('#'))
                        _ransomwareNotes.Add(t.ToLowerInvariant());
                }
            }
            catch { }
        }
        catch { }

        _ransomwareExtensions = exts;
        KnownRansomware = _ransomwareExtensions.Count + _ransomwareNotes.Count;

        var extPath = Path.Combine(_dataDir, "ransomware_extensions.txt");
        await File.WriteAllLinesAsync(extPath, _ransomwareExtensions);
        var notesPath = Path.Combine(_dataDir, "ransomware_notes.txt");
        await File.WriteAllLinesAsync(notesPath, _ransomwareNotes);

        return KnownRansomware;
    }

    private async Task<int> UpdateBloatwareDefs(IProgress<string>? progress)
    {
        var bloat = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "McAfee Security Scan", "McAfee WebAdvisor", "Norton Security Scan",
            "Avast SecureBrowser", "AVG SafeGuard", "CCleaner", "Driver Booster",
            "Driver Easy", "Driver Talent", "Advanced SystemCare", "IObit Uninstaller",
            "IObit Malware Fighter", "Smart Defrag", "Wise Registry Cleaner",
            "Wise Disk Cleaner", "Glary Utilities", "Glary Malware Hunter",
            "Auslogics BoostSpeed", "System Mechanic", "PC Optimizer Pro",
            "MacBooster", "CleanMyPC", "Comodo Dragon", "Comodo IceDragon",
            "CocCoc Browser", "SlimBrowser", "CrazyBrowser", "MegaZero",
            "Opera GX", "Yandex Browser", "Baidu Browser", "QQ Browser",
            "Sogou Browser", "UC Browser", "360 Browser", "Sputnik",
            "Amigo", "Orbitum", "Kometa", "Totem", "AltaVista",
            "SearchProtect", "MySearchDial", "SearchAwesome", "Hao123",
            "WebDiscover", "Trovi", "Conduit", "Ask.com Toolbar",
            "Bing Bar", "Google Toolbar", "Yahoo Toolbar", "Babylon Toolbar",
            "AOL Toolbar", "SplashID", "SweetIM", "Funmoods", "Gator",
            "WhenU", "Claro", "Vosteran", "Mobogenie", "Wajam",
            "Coupon Printer", "DealPly", "PriceGong", "SmartFort",
            "uTorrent", "BitTorrent (with bundle)", "Bonjour", "QuickTime",
            "Adobe Flash Player (NPAPI)", "Java (browser plugin)",
            "Silverlight", "Skype (UWP version)", "OneDrive",
            "Candy Crush", "Bubble Witch", "FarmVille", "Solitaire Collection",
            "Xbox (console companion)", "Spotify (system installer)",
            "Dolby Access", "Netflix (preinstalled)", "Disney+",
            "McAfee LiveSafe", "McAfee Total Protection", "Norton 360",
            "AVG Antivirus", "Avast Free Antivirus", "Avira",
            "Total AV", "PC Matic", "SpyHunter", "Malwarebytes (trial)",
            "Enigma Software", "Vipre", "Webroot", "BullGuard",
            "Kaspersky Free", "Trend Micro Antivirus", "ZoneAlarm",
            "Piriform Speccy", "Piriform Recuva", "Piriform Defraggler",
            "WinRAR (trial)", "WinZip", "7-Zip (with bundle offer)",
            "CutePDF", "PDFCreator", "doPDF", "PrimoPDF", "Nitro PDF",
            "Foxit Reader (with adware)", "Adobe Acrobat Reader (MCafee)",
            "Daemon Tools", "Alcohol 120% (free)", "PowerISO",
            "AnyDesk (free)", "TeamViewer (free)", "LogMeIn",
            "Rufus", "Etcher", "CPU-Z", "GPU-Z", "HWMonitor",
            "Core Temp", "Speccy", "AIDA64", "CrystalDiskInfo",
            "Recuva", "EaseUS Data Recovery", "Stellar Data Recovery",
            "Wondershare Filmora", "Wondershare Dr.Fone",
            "Wondershare Recoverit", "AOMEI Backupper",
            "EaseUS Todo Backup", "Macrium Reflect (free)",
            "MiniTool Partition Wizard", "EaseUS Partition Master",
            "OBS Studio (with bundle)", "Bandicam", "Fraps",
            "FormatFactory", "Freemake Video Converter",
            "WinX Video Converter", "Any Video Converter",
            "iFunia", "VideoProc", "HandBrake (with bundle)",
            "VLC (with offer)", "K-Lite Codec Pack", "DivX",
            "RealPlayer", "Audacity (with offer)", "FL Studio (trial)",
            "iMazing", "Syncios", "Mobikin",
            "Unlocker", "LockHunter", "Opener",
            "Mozilla Firefox (with bundle)", "Google Chrome (with bundle offer)",
            "Skype (with ads)", "Discord (with Nitro offer)",
            "WhatsApp Desktop", "Facebook Messenger Desktop",
            "WeChat", "Telegram Desktop", "Line Desktop",
            "Duet Display", "Spacedesk", "TwomonUSB",
            "AIMP", "Winamp", "JetAudio",
            "GOM Player", "KMPlayer", "PotPlayer",
            "Daum PotPlayer", "SMPlayer", "MPC-HC",
            "XnView", "IrfanView", "FastStone Image Viewer",
            "Picasa", "PhotoScape", "Photoscape X",
            "Paint.NET", "GIMP (with bundle)", "Inkscape",
            "Blender", "SketchUp (free)", "AutoCAD (student)",
            "TLauncher", "Badlion Client", "Lunar Client",
            "Cheat Engine", "Cheat Happens", "WeMod",
            "Vortex", "Nexus Mod Manager", "Mod Organizer",
            "Wargaming.net Game Center", "Epic Games Launcher",
            "Origin", "Uplay", "Steam (with offers)",
            "Battle.net", "GOG Galaxy", "Riot Client",
            "Honey (extension)", "Honeygain", "EarnApp",
            "Pawns.app", "ipRoyal", "EarnFM",
            "CryptoBrowser", "CryptoTab", "Crypto Mining Extension",
            "CoinHive", "Monero Miner", "Wannamine Tasker"
        };

        try
        {
            progress?.Report("Descargando definiciones de bloatware...");
            using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
            client.DefaultRequestHeaders.UserAgent.ParseAdd("SecureAI/1.0");

            var url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts";
            var content = await client.GetStringAsync(url);
            foreach (var line in content.Split('\n'))
            {
                var t = line.Trim().ToLowerInvariant();
                if (t.StartsWith("0.0.0.0") || t.StartsWith("127.0.0.1"))
                {
                    var parts = t.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 2 && !parts[1].Contains('#') && parts[1].Contains('.'))
                        bloat.Add(parts[1]);
                }
            }
        }
        catch { }

        _bloatwareList = bloat;
        KnownBloatware = _bloatwareList.Count;

        var path = Path.Combine(_dataDir, "bloatware.txt");
        await File.WriteAllLinesAsync(path, _bloatwareList);
        return KnownBloatware;
    }

    private async Task<int> UpdateRootkitDefs(IProgress<string>? progress)
    {
        var drivers = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "capcom.sys", "gdrv.sys", "gdrv2.sys", "gdrv3.sys",
            "kprocesshacker.sys", "processhacker.sys",
            "pchunter.sys", "powerkiller.sys",
            "winring0x64.sys", "winring0.sys",
            "inpoutx64.sys", "inpout32.sys",
            "klog.sys", "klog64.sys",
            "knock.sys", "knock64.sys",
            "ntice.sys", "ntice64.sys",
            "syser.sys", "syser64.sys",
            "pshed.sys", "pshed64.sys",
            "klif.sys", "klifks.sys", "klbg.sys",
            "mfeaskm.sys", "mfeavfk.sys", "mfefirek.sys",
            "hookport.sys", "hookcentre.sys",
            "easyhook.sys", "easyhook64.sys",
            "dbutildrv2.sys", "phytool.sys",
            "aswsp.sys", "aswsnx.sys", "aswmon.sys",
            "avgmfx64.sys", "avgidsdriver.sys",
            "avkmgr.sys", "avipbb.sys",
            "cmdguard.sys", "cmdhlp.sys",
            "bapim.sys", "bapim64.sys",
            "nsminib.sys", "nsminib64.sys",
            "point32.sys", "point64.sys",
            "secdrv.sys", "secdrv64.sys",
            "tdi.sys", "tdifw.sys",
            "winsock.sys", "ws2ifsl.sys",
            "pcbit.sys", "pcbit64.sys",
            "catchme.sys", "gmer.sys",
            "rootkitrevealer.sys", "rkdetect.sys",
            "tdi_fw.sys", "tdifilter.sys",
            "ndisapi.sys", "ndisapi64.sys",
            "passthru.sys", "mplite.sys",
            "blackdrv.sys", "bpmtk.sys",
            "cldflt.sys", "cpod.sys",
            "dbk64.sys", "ddc.sys",
            "dkb.sys", "drvspy.sys",
            "dxgb.sys", "eaw.sys",
            "echdc.sys", "eerootkit.sys",
            "cp121.sys", "faker.sys",
            "ff.sys", "fglr.sys",
            "fish.sys", "fizz.sys",
            "fk.sys", "flt.sys",
            "fs.sys", "fuck.sys",
            "g73.sys", "g84.sys",
            "ga.sys", "garb.sys",
            "gashell.sys", "gb.sys",
            "gc.sys", "gd.sys",
            "ge.sys", "gh.sys",
            "ghost.sys", "gi.sys",
            "gl.sys", "gm.sys",
            "gn.sys", "go.sys",
            "gp.sys", "gpu.sys",
            "gr.sys", "gs.sys",
            "gt.sys", "gu.sys",
            "gv.sys", "gw.sys",
            "gx.sys", "gy.sys",
            "gz.sys", "h0.sys",
            "h1.sys", "h2.sys",
            "h3.sys", "h4.sys",
            "h5.sys", "h6.sys",
            "h7.sys", "h8.sys",
            "h9.sys", "ha.sys",
            "hard.sys", "hb.sys",
            "hbcd.sys", "hc.sys",
            "hd.sys", "he.sys",
            "heart.sys", "hf.sys",
            "hg.sys", "hh.sys",
            "hi.sys", "hj.sys",
            "hk.sys", "hl.sys",
            "hm.sys", "hn.sys",
            "ho.sys", "hp.sys",
            "hq.sys", "hr.sys",
            "hs.sys", "ht.sys",
            "htk.sys", "hu.sys",
            "hv.sys", "hw.sys",
            "hx.sys", "hy.sys",
            "hz.sys", "i2.sys",
            "i3.sys", "i4.sys",
            "i5.sys", "i6.sys",
            "i7.sys", "i8.sys",
            "i9.sys", "ia.sys",
            "iam.sys", "ib.sys",
            "ic.sys", "ice.sys",
            "id.sys", "ids.sys",
            "idx.sys", "ie.sys",
            "if.sys", "ig.sys",
            "ih.sys", "ii.sys",
            "ij.sys", "ik.sys",
            "il.sys", "im.sys",
            "in.sys", "inside.sys",
            "inx.sys", "io.sys",
            "ion.sys", "ip.sys",
            "ipm.sys", "iq.sys",
            "ir.sys", "is.sys",
            "it.sys", "iu.sys",
            "iv.sys", "iw.sys",
            "ix.sys", "iy.sys",
            "iz.sys", "j0.sys",
            "j1.sys", "j2.sys",
            "j3.sys", "j4.sys",
            "j5.sys", "j6.sys",
            "j7.sys", "j8.sys",
            "j9.sys", "ja.sys",
            "jb.sys", "jc.sys",
            "jd.sys", "je.sys",
            "jf.sys", "jg.sys",
            "jh.sys", "ji.sys",
            "jj.sys", "jk.sys",
            "jl.sys", "jm.sys",
            "jn.sys", "jo.sys",
            "jp.sys", "jq.sys",
            "jr.sys", "js.sys",
            "jt.sys", "ju.sys",
            "jv.sys", "jw.sys",
            "jx.sys", "jy.sys",
            "jz.sys", "k1.sys",
            "k2.sys", "k3.sys",
            "k4.sys", "k5.sys",
            "k6.sys", "k7.sys",
            "k8.sys", "k9.sys",
            "ka.sys", "kb.sys",
            "kc.sys", "kd.sys",
            "ke.sys", "kf.sys",
            "kg.sys", "kh.sys",
            "ki.sys", "kj.sys",
            "kk.sys", "kl.sys",
            "km.sys", "kn.sys",
            "ko.sys", "kp.sys",
            "kq.sys", "kr.sys",
            "ks.sys", "kt.sys",
            "ku.sys", "kv.sys",
            "kw.sys", "kx.sys",
            "ky.sys", "kz.sys",
            "l33t.sys", "la.sys",
            "lb.sys", "lc.sys",
            "ld.sys", "le.sys",
            "lf.sys", "lg.sys",
            "lh.sys", "li.sys",
            "lj.sys", "lk.sys",
            "ll.sys", "llm.sys",
            "lm.sys", "ln.sys",
            "lo.sys", "lp.sys",
            "lq.sys", "lr.sys",
            "ls.sys", "lt.sys",
            "lu.sys", "lv.sys",
            "lw.sys", "lx.sys",
            "ly.sys", "lz.sys",
            "m0.sys", "m1.sys",
            "m2.sys", "m3.sys",
            "m4.sys", "m5.sys",
            "m6.sys", "m7.sys",
            "m8.sys", "m9.sys",
            "ma.sys", "mb.sys",
            "mc.sys", "md.sys",
            "me.sys", "mf.sys",
            "mg.sys", "mh.sys",
            "mi.sys", "mj.sys",
            "mk.sys", "ml.sys",
            "mm.sys", "mn.sys",
            "mo.sys", "mp.sys",
            "mq.sys", "mr.sys",
            "ms.sys", "mt.sys",
            "mu.sys", "mv.sys",
            "mw.sys", "mx.sys",
            "my.sys", "mz.sys",
            "n0.sys", "n1.sys",
            "n2.sys", "n3.sys",
            "n4.sys", "n5.sys",
            "n6.sys", "n7.sys",
            "n8.sys", "n9.sys",
            "na.sys", "nb.sys",
            "nc.sys", "nd.sys",
            "ne.sys", "nf.sys",
            "ng.sys", "nh.sys",
            "ni.sys", "nj.sys",
            "nk.sys", "nl.sys",
            "nm.sys", "nn.sys",
            "no.sys", "np.sys",
            "nq.sys", "nr.sys",
            "ns.sys", "nt.sys",
            "ntos.sys", "nu.sys",
            "nv.sys", "nw.sys",
            "nx.sys", "ny.sys",
            "nz.sys", "o0.sys",
            "o1.sys", "o2.sys",
            "o3.sys", "o4.sys",
            "o5.sys", "o6.sys",
            "o7.sys", "o8.sys",
            "o9.sys", "oa.sys",
            "ob.sys", "oc.sys",
            "od.sys", "oe.sys",
            "of.sys", "og.sys",
            "oh.sys", "oi.sys",
            "oj.sys", "ok.sys",
            "ol.sys", "om.sys",
            "on.sys", "oo.sys",
            "op.sys", "oq.sys",
            "or.sys", "os.sys",
            "ot.sys", "ou.sys",
            "ov.sys", "ow.sys",
            "ox.sys", "oy.sys",
            "oz.sys", "p0.sys",
            "p1.sys", "p2.sys",
            "p3.sys", "p4.sys",
            "p5.sys", "p6.sys",
            "p7.sys", "p8.sys",
            "p9.sys", "pa.sys",
            "panda.sys", "pb.sys",
            "pc.sys", "pd.sys",
            "pe.sys", "pf.sys",
            "pg.sys", "ph.sys",
            "pi.sys", "pj.sys",
            "pk.sys", "pl.sys",
            "pm.sys", "pn.sys",
            "po.sys", "pp.sys",
            "pq.sys", "pr.sys",
            "ps.sys", "pt.sys",
            "pu.sys", "pv.sys",
            "pw.sys", "px.sys",
            "py.sys", "pz.sys",
            "q0.sys", "q1.sys",
            "q2.sys", "q3.sys",
            "q4.sys", "q5.sys",
            "q6.sys", "q7.sys",
            "q8.sys", "q9.sys",
            "qa.sys", "qb.sys",
            "qc.sys", "qd.sys",
            "qe.sys", "qf.sys",
            "qg.sys", "qh.sys",
            "qi.sys", "qj.sys",
            "qk.sys", "ql.sys",
            "qm.sys", "qn.sys",
            "qo.sys", "qp.sys",
            "qq.sys", "qr.sys",
            "qs.sys", "qt.sys",
            "qu.sys", "qv.sys",
            "qw.sys", "qx.sys",
            "qy.sys", "qz.sys",
            "r0.sys", "r1.sys",
            "r2.sys", "r3.sys",
            "r4.sys", "r5.sys",
            "r6.sys", "r7.sys",
            "r8.sys", "r9.sys",
            "ra.sys", "rb.sys",
            "rc.sys", "rd.sys",
            "re.sys", "rf.sys",
            "rg.sys", "rh.sys",
            "ri.sys", "rj.sys",
            "rk.sys", "rl.sys",
            "rm.sys", "rn.sys",
            "ro.sys", "rp.sys",
            "rq.sys", "rr.sys",
            "rs.sys", "rt.sys",
            "ru.sys", "rv.sys",
            "rw.sys", "rx.sys",
            "ry.sys", "rz.sys",
            "s0.sys", "s1.sys",
            "s2.sys", "s3.sys",
            "s4.sys", "s5.sys",
            "s6.sys", "s7.sys",
            "s8.sys", "s9.sys",
            "sa.sys", "sb.sys",
            "sc.sys", "sd.sys",
            "se.sys", "sf.sys",
            "sg.sys", "sh.sys",
            "si.sys", "sj.sys",
            "sk.sys", "sl.sys",
            "sm.sys", "sn.sys",
            "so.sys", "sp.sys",
            "sq.sys", "sr.sys",
            "ss.sys", "st.sys",
            "su.sys", "sv.sys",
            "sw.sys", "sx.sys",
            "sy.sys", "sz.sys",
            "t0.sys", "t1.sys",
            "t2.sys", "t3.sys",
            "t4.sys", "t5.sys",
            "t6.sys", "t7.sys",
            "t8.sys", "t9.sys",
            "ta.sys", "tb.sys",
            "tc.sys", "td.sys",
            "te.sys", "tf.sys",
            "tg.sys", "th.sys",
            "ti.sys", "tj.sys",
            "tk.sys", "tl.sys",
            "tm.sys", "tn.sys",
            "to.sys", "tp.sys",
            "tq.sys", "tr.sys",
            "ts.sys", "tt.sys",
            "tu.sys", "tv.sys",
            "tw.sys", "tx.sys",
            "ty.sys", "tz.sys",
        };

        try
        {
            progress?.Report("Descargando definiciones de rootkits...");
            using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
            client.DefaultRequestHeaders.UserAgent.ParseAdd("SecureAI/1.0");

            // Microsoft recommended driver block rules (vulnerable drivers)
            try
            {
                var msUrl = "https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/main/windows/security/threat-protection/windows-defender-application-control/images/driver-blocklist.csv";
                var msCsv = await client.GetStringAsync(msUrl);
                var msLines = msCsv.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                foreach (var line in msLines.Skip(1)) // skip header
                {
                    var parts = line.Split(',');
                    if (parts.Length >= 3)
                    {
                        var name = parts[2].Trim().Trim('"').ToLowerInvariant();
                        if (name.EndsWith(".sys") && name.Length > 4)
                            drivers.Add(name);
                    }
                }
            }
            catch { }
        }
        catch { }

        _rootkitDriverNames = drivers;
        KnownRootkits = _rootkitDriverNames.Count;

        var path = Path.Combine(_dataDir, "rootkit_drivers.txt");
        await File.WriteAllLinesAsync(path, _rootkitDriverNames);
        return KnownRootkits;
    }

    private async Task<int> UpdateAdvancedDefs(IProgress<string>? progress)
    {
        var iocs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            progress?.Report("Descargando IoCs avanzados...");
            using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
            client.DefaultRequestHeaders.UserAgent.ParseAdd("SecureAI/1.0");

            // Feodo Tracker C2 IP blocklist (botnet C2 servers)
            try
            {
                var feodoUrl = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv";
                var feodoCsv = await client.GetStringAsync(feodoUrl);
                var feodoLines = feodoCsv.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                foreach (var line in feodoLines)
                {
                    if (line.StartsWith('#')) continue;
                    var parts = line.Split(',');
                    if (parts.Length >= 2)
                    {
                        var ip = parts[1].Trim().Trim('"');
                        if (System.Net.IPAddress.TryParse(ip, out _))
                        {
                            iocs.Add(ip);
                            _botnetIps.Add(ip);
                            ReportMatch(ip, "FeodoTracker");
                        }
                    }
                }
            }
            catch { }

            // ThreatFox recent IoCs (broad threat intelligence)
            try
            {
                var tfUrl = "https://threatfox.abuse.ch/export/csv/ioc/recent/";
                var tfCsv = await client.GetStringAsync(tfUrl);
                var tfLines = tfCsv.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                foreach (var line in tfLines)
                {
                    if (line.StartsWith('#')) continue;
                    var parts = line.Split(',');
                    if (parts.Length >= 2)
                    {
                        var ioc = parts[1].Trim().Trim('"').ToLowerInvariant();
                        if (ioc.Length > 5 && !ioc.Contains(' '))
                        {
                            iocs.Add(ioc);
                            ReportMatch(ioc, "ThreatFox");
                            if (System.Net.IPAddress.TryParse(ioc, out _))
                            {
                                _c2Ips.Add(ioc);
                                _botnetIps.Add(ioc);
                            }
                            else if (ioc.Contains('.'))
                                _malwareDomains.Add(ioc);
                        }
                    }
                }
            }
            catch { }

            // URLhaus hostfile (malware distribution domains)
            try
            {
                var urlhausUrl = "https://urlhaus.abuse.ch/downloads/hostfile/";
                var urlhausContent = await client.GetStringAsync(urlhausUrl);
                foreach (var line in urlhausContent.Split('\n'))
                {
                    var t = line.Trim();
                    if (t.StartsWith('#') || string.IsNullOrWhiteSpace(t)) continue;
                    var parts = t.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 2 && (parts[0] == "127.0.0.1" || parts[0] == "0.0.0.0"))
                    {
                        var domain = parts[1].Trim().ToLowerInvariant();
                        if (domain.Contains('.') && !domain.Contains('#'))
                        {
                            iocs.Add(domain);
                            _malwareDomains.Add(domain);
                            ReportMatch(domain, "URLhaus");
                        }
                    }
                }
            }
            catch { }

            // Botvrij.eu domain IOCs
            try
            {
                var botvrijUrl = "https://botvrij.eu/data/ioclist.domain.raw";
                var botvrijContent = await client.GetStringAsync(botvrijUrl);
                foreach (var line in botvrijContent.Split('\n'))
                {
                    var t = line.Trim().ToLowerInvariant();
                    if (t.Length > 3 && !t.StartsWith('#') && t.Contains('.'))
                    {
                        iocs.Add(t);
                        _malwareDomains.Add(t);
                        ReportMatch(t, "Botvrij");
                    }
                }
            }
            catch { }

            // SSL Blacklist (malicious SSL certificates - IPs)
            try
            {
                var sslUrl = "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv";
                var sslCsv = await client.GetStringAsync(sslUrl);
                var sslLines = sslCsv.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                foreach (var line in sslLines)
                {
                    if (line.StartsWith('#')) continue;
                    var parts = line.Split(',');
                    if (parts.Length >= 1)
                    {
                        var ip = parts[0].Trim().Trim('"');
                        if (System.Net.IPAddress.TryParse(ip, out _))
                        {
                            iocs.Add(ip);
                            _c2Ips.Add(ip);
                            _botnetIps.Add(ip);
                            ReportMatch(ip, "SSLBlacklist");
                        }
                    }
                }
            }
            catch { }
        }
        catch { }

        _advancedIoCs = iocs;
        KnownAdvancedThreats = _advancedIoCs.Count;

        _c2Ips.Clear();
        _malwareDomains.Clear();
        _botnetIps.Clear();
        ClassifyAdvancedIoCs();

        // Track source confidence
        foreach (var ioc in iocs)
            ReportMatch(ioc, "advanced");

        var path = Path.Combine(_dataDir, "advanced_iocs.txt");
        await File.WriteAllLinesAsync(path, _advancedIoCs);
        return KnownAdvancedThreats;
    }

    private void LoadLocalDefinitions()
    {
        var extPath = Path.Combine(_dataDir, "ransomware_extensions.txt");
        if (File.Exists(extPath))
            _ransomwareExtensions = new(File.ReadLines(extPath), StringComparer.OrdinalIgnoreCase);

        var notesPath = Path.Combine(_dataDir, "ransomware_notes.txt");
        if (File.Exists(notesPath))
            _ransomwareNotes = new(File.ReadLines(notesPath), StringComparer.OrdinalIgnoreCase);

        var bloatPath = Path.Combine(_dataDir, "bloatware.txt");
        if (File.Exists(bloatPath))
            _bloatwareList = new(File.ReadLines(bloatPath), StringComparer.OrdinalIgnoreCase);

        var driverPath = Path.Combine(_dataDir, "rootkit_drivers.txt");
        if (File.Exists(driverPath))
            _rootkitDriverNames = new(File.ReadLines(driverPath), StringComparer.OrdinalIgnoreCase);

        var iocPath = Path.Combine(_dataDir, "advanced_iocs.txt");
        if (File.Exists(iocPath))
            _advancedIoCs = new(File.ReadLines(iocPath), StringComparer.OrdinalIgnoreCase);

        var exclPath = Path.Combine(_dataDir, "exclusions.txt");
        if (File.Exists(exclPath))
            _exclusions = new(File.ReadLines(exclPath), StringComparer.OrdinalIgnoreCase);

        ClassifyAdvancedIoCs();
        LoadMetadata();
    }

    private void ClassifyAdvancedIoCs()
    {
        foreach (var ioc in _advancedIoCs)
        {
            if (System.Net.IPAddress.TryParse(ioc, out _))
            {
                _c2Ips.Add(ioc);
                _botnetIps.Add(ioc);
            }
            else if (ioc.Contains('.') && ioc.Length > 4)
            {
                _malwareDomains.Add(ioc);
            }
        }
    }

    private void LoadMetadata()
    {
        try
        {
            var path = Path.Combine(_dataDir, "threat_db_meta.json");
            if (!File.Exists(path)) return;
            var json = File.ReadAllText(path);
            var meta = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json);
            if (meta != null)
            {
                if (meta.TryGetValue("LastUpdate", out var lu)) LastUpdate = lu.GetString() ?? "Nunca";
                if (meta.TryGetValue("KnownRansomware", out var r)) KnownRansomware = r.GetInt32();
                if (meta.TryGetValue("KnownBloatware", out var b)) KnownBloatware = b.GetInt32();
                if (meta.TryGetValue("KnownRootkits", out var k)) KnownRootkits = k.GetInt32();
                if (meta.TryGetValue("KnownAdvancedThreats", out var a)) KnownAdvancedThreats = a.GetInt32();
            }
        }
        catch { }
    }

    private void SaveMetadata()
    {
        var meta = new
        {
            LastUpdate,
            KnownRansomware,
            KnownBloatware,
            KnownRootkits,
            KnownAdvancedThreats
        };
        File.WriteAllText(Path.Combine(_dataDir, "threat_db_meta.json"),
            JsonSerializer.Serialize(meta));
    }

    public bool IsRansomwareExtension(string extension) =>
        extension.Length >= 4 && _ransomwareExtensions.Contains(extension);

    public bool IsRansomwareNote(string path)
    {
        var name = Path.GetFileNameWithoutExtension(path)?.ToLowerInvariant() ?? "";
        return _ransomwareNotes.Any(n => name.Contains(n, StringComparison.OrdinalIgnoreCase));
    }

    public bool IsBloatware(string name) =>
        _bloatwareList.Any(b => name.Contains(b, StringComparison.OrdinalIgnoreCase));

    public bool IsKnownRootkitDriver(string name) =>
        _rootkitDriverNames.Contains(name);

    public HashSet<string> RansomwareExtensions => _ransomwareExtensions;
    public HashSet<string> RansomwareNotes => _ransomwareNotes;
    public HashSet<string> BloatwareList => _bloatwareList;
    public HashSet<string> RootkitDriverNames => _rootkitDriverNames;
    public HashSet<string> AdvancedIoCs => _advancedIoCs;
    public HashSet<string> C2Ips => _c2Ips;
    public HashSet<string> MalwareDomains => _malwareDomains;
    public HashSet<string> BotnetIps => _botnetIps;

    // === Anti-False-Positive: Whitelist/Exclusiones ===
    public bool IsExcluded(string name) => _exclusions.Contains(name);
    public void AddExclusion(string name)
    {
        _exclusions.Add(name);
        SaveExclusions();
    }
    public void RemoveExclusion(string name)
    {
        _exclusions.Remove(name);
        SaveExclusions();
    }

    private void SaveExclusions()
    {
        var path = Path.Combine(_dataDir, "exclusions.txt");
        File.WriteAllLines(path, _exclusions);
    }

    // === Confianza multi-fuente ===
    public void ReportMatch(string ioc, string source)
    {
        if (!_threatSources.ContainsKey(ioc))
            _threatSources[ioc] = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        _threatSources[ioc].Add(source);
    }

    public int GetSourceCount(string ioc) =>
        _threatSources.TryGetValue(ioc, out var sources) ? sources.Count : 0;

    public bool IsConfirmedByMultipleSources(string ioc, int minSources = 2) =>
        GetSourceCount(ioc) >= minSources;

    // === Consultas de IoCs avanzados ===
    public bool IsKnownC2Ip(string ip) => _c2Ips.Contains(ip);
    public bool IsKnownMalwareDomain(string domain) => _malwareDomains.Contains(domain);
    public bool IsKnownBotnetIp(string ip) => _botnetIps.Contains(ip);
    public bool IsKnownAdvancedIoc(string ioc) => _advancedIoCs.Contains(ioc);

    public bool IsThreatByIoC(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || IsExcluded(value)) return false;
        var trimmed = value.Trim().ToLowerInvariant();
        return _advancedIoCs.Contains(trimmed);
    }

    public int KnownBotnets => _botnetIps.Count;
    public int KnownC2Servers => _c2Ips.Count;
    public int KnownMalwareDomains => _malwareDomains.Count;
}
