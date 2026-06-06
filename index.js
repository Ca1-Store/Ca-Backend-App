const express = require("express");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const fetch = (...args) => import("node-fetch").then(({ default: fetch }) => fetch(...args));

const app = express();
app.use(express.json());

const db = new Pool({ connectionString: process.env.DATABASE_URL });
const JWT_SECRET = process.env.JWT_SECRET;
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const DISCORD_GUILD_ID = process.env.DISCORD_GUILD_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const CLIENT_ID = process.env.DISCORD_CLIENT_ID;

const ROLE_PLAN_MAP = {
    "1479829127715618866": "CA-1",
    "1479829984385171557": "CA-2",
    "1502945235817467974": "CA-3",
    "1509080955858456687": "CA-4",
};

db.query(`
    CREATE TABLE IF NOT EXISTS users (
        discord_id TEXT PRIMARY KEY,
        hwid TEXT,
        last_login TIMESTAMP
    )
`).catch(err => console.error("DB init error:", err));

/* ============================================================
   helper: جيب كل النسخ اللي عند المستخدم من Discord
============================================================ */
async function getPlansFromDiscord(discordId) {
    const memberRes = await fetch(
        `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${discordId}`,
        { headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` } }
    );
    const member = await memberRes.json();

    if (!member.roles) return null;

    // رجّع كل النسخ اللي عنده
    const plans = [];
    for (const roleId of member.roles) {
        if (ROLE_PLAN_MAP[roleId]) {
            plans.push(ROLE_PLAN_MAP[roleId]);
        }
    }

    return plans.length > 0 ? plans : null;
}

/* ============================================================
   خطوة 1: البرنامج يطلب رابط OAuth
============================================================ */
app.get("/auth/url", (req, res) => {
    const url = `https://discord.com/oauth2/authorize?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent("http://localhost:7842/callback")}&response_type=code&scope=identify%20guilds.members.read`;
    res.json({ url });
});

/* ============================================================
   خطوة 2: استقبال الكود من Discord وتبديله بـ token
============================================================ */
app.post("/auth/callback", async (req, res) => {
    const { code, hwid } = req.body;

    if (!code || !hwid) return res.json({ success: false, message: "بيانات ناقصة" });

    try {
        const tokenRes = await fetch("https://discord.com/api/oauth2/token", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
                client_id: CLIENT_ID,
                client_secret: CLIENT_SECRET,
                grant_type: "authorization_code",
                code,
                redirect_uri: "http://localhost:7842/callback"
            })
        });

        const tokenData = await tokenRes.json();

        if (!tokenData.access_token) {
            console.error("❌ OAuth failed:", tokenData);
            return res.json({ success: false, message: "فشل OAuth" });
        }

        const userRes = await fetch("https://discord.com/api/users/@me", {
            headers: { Authorization: `Bearer ${tokenData.access_token}` }
        });
        const user = await userRes.json();
        const discordId = user.id;

        // التحقق من HWID
        const existing = await db.query("SELECT * FROM users WHERE discord_id=$1", [discordId]);

        if (existing.rows.length > 0) {
            if (existing.rows[0].hwid !== hwid) {
                return res.json({
                    success: false,
                    message: "هذا الحساب مسجّل على جهاز مختلف. تواصل مع الدعم."
                });
            }
        } else {
            await db.query(
                "INSERT INTO users (discord_id, hwid, last_login) VALUES ($1,$2,NOW())",
                [discordId, hwid]
            );
        }

        // جيب كل النسخ من Discord
        const plans = await getPlansFromDiscord(discordId);

        if (!plans) return res.json({ success: false, message: "ما عندك نسخة فعّالة في السيرفر" });

        const token = jwt.sign(
            { discordId, hwid },
            JWT_SECRET,
            { expiresIn: "30d" }
        );

        await db.query("UPDATE users SET last_login=NOW() WHERE discord_id=$1", [discordId]);

        return res.json({ success: true, token, plans, username: user.username, discordId: discordId });

    } catch (err) {
        console.error("❌ Callback error:", err);
        return res.json({ success: false, message: "خطأ في السيرفر" });
    }
});

/* ============================================================
   خطوة 3: التحقق عند كل فتح - يتحقق من Discord مباشرة
============================================================ */
app.post("/auth/verify", async (req, res) => {
    const { token, hwid } = req.body;

    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        if (decoded.hwid !== hwid) {
            return res.json({ success: false, message: "جهاز غير مطابق" });
        }

        // جيب كل النسخ الحالية من Discord مباشرة
        const plans = await getPlansFromDiscord(decoded.discordId);

        if (!plans) {
            return res.json({ success: false, message: "انتهت صلاحية نسختك أو تم إلغاؤها" });
        }

        return res.json({ success: true, plans, discordId: decoded.discordId });

    } catch {
        return res.json({ success: false, message: "Token منتهي أو غير صالح" });
    }
});
/* ============================================================
   API: جلب بيانات الـ Packs مع نظام الـ Versions
============================================================ */
app.get("/api/packs", async (req, res) => {
    const packs = [
        {
            id: "CA1",
            plan: "CA-1",
            name: "CA - Pack 1",
            level: 1,
            images: ["../assets/Ca--Pack.png", "../assets/Ca-1.png", "../assets/Ca-1v1.png"],
            url: "http://213.199.63.97/CA-1%20PACK.zip",
            versions: [
                {
                    version: "1.0",
                    date: "2026-03-18",
                    latest: true,
                    size: "1.80 GB",
                    features: ["الإصدار الأولي", "جرافيكس أساسي"],
                    changelog: "الإصدار الأولي من باك الجرافيكس",
                    url: "http://213.199.63.97/CA-1%20PACK.zip"
                }
            ]
        },
        {
            id: "CA2",
            plan: "CA-2",
            name: "CA - Pack 2",
            level: 2,
            images: ["../assets/Ca-Pack.png", "../assets/Ca-2v2.png", "../assets/Ca_Store.png"],
            url: "http://213.199.63.97/CA-2%20PACK.zip",
            versions: [
                {
                    version: "1.0",
                    date: "2026-05-20",
                    latest: true,
                    size: "276 MB",
                    features: ["جرافيكس محسّن", "أداء أفضل"],
                    changelog: "الإصدار الأولي مع تحسينات على الجرافيكس",
                    url: "http://213.199.63.97/CA-2%20PACK.zip"
                }
            ]
        },
        {
            id: "CA3",
            plan: "CA-3",
            name: "CA - Pack 3",
            level: 3,
            images: ["../assets/ca333.png", "../assets/ca3.png", "../assets/ca33.png"],
            url: "http://213.199.63.97/CA-3%20PACK.zip",
            versions: [
                {
                    version: "1.0",
                    date: "2026-05-25",
                    latest: true,
                    size: "733 MB",
                    features: ["جرافيكس عالي الجودة", "إضاءة محسّنة"],
                    changelog: "الإصدار الأولي مع جرافيكس عالي الجودة",
                    url: "http://213.199.63.97/CA-3%20PACK.zip"
                }
            ]
        },
        {
            id: "CA4",
            plan: "CA-4",
            name: "CA - Pack 4",
            level: 4,
            images: ["../assets/ca444.png", "../assets/ca4.png", "../assets/ca44.png"],
            url: "http://213.199.63.97/CA-4%20PACK.zip",
            versions: [
                {
                    version: "1.0.1",
                    date: "2026-06-6",
                    latest: true,
                    size: "700 MB",
                    features: ["تخفيف الحجم", "زيادة الفريمات", "أداء محسّن"],
                    changelog: "تحديث رئيسي مع تحسينات كبيرة في الأداء وزيادة الفريمات",
                    url: "http://213.199.63.97/CA-4-PACK-v1.0.1.zip"
                },
                {
                    version: "1.0",
                    date: "2026-05-28",
                    latest: false,
                    size: "900 MB",
                    features: ["الإصدار الأولي", "جرافيكس فائق"],
                    changelog: "الإصدار الأولي من باك الجرافيكس فائق الجودة",
                    url: "http://213.199.63.97/CA-4%20PACK.zip"
                }
            ]
        }
    ];
    res.json({ success: true, packs });
});
/* ============================================================
   API: جلب بيانات المودات
============================================================ */
app.get("/api/mods", async (req, res) => {
    const sections = [
        {
            title: "Roads",
            subtitle: "تحتاج أي نسخة",
            icon: `<svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 17L9 3l6 14"/><path d="M6 11h6"/></svg>`,
            requiredPlans: ["CA-1", "CA-2", "CA-3", "CA-4"],
            mods: [
                { name: "European Roads", file: "European_Roads.rpf", img: "../assets/Europe.png", url: "http://213.199.63.97/European_Roads.rpf" },
                { name: "German Roads", file: "German_Roads.rpf", img: "../assets/German_Roads.png", url: "http://213.199.63.97/German_Roads.rpf" },
                { name: "NVE Roads", file: "Ls_Roads_Pack.rpf", img: "../assets/nve.png", url: "http://213.199.63.97/Ls_Roads_Pack.rpf" },
                { name: "Liberty Roads", file: "Liberty_Roads.rpf", img: "../assets/Liberty.png", url: "http://213.199.63.97/Liberty_Roads.rpf" }
            ]
        },
        {
            title: "Vegetation",
            subtitle: "تحتاج النسخة الثانية أو الثالثة",
            icon: `<svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 22V12"/><path d="M12 12C12 7 7 4 7 4s0 5 5 8"/><path d="M12 12c0-5 5-8 5-8s0 5-5 8"/></svg>`,
            requiredPlans: ["CA-2", "CA-3", "CA-4"],
            mods: [
                { name: "Vegetation", file: "CA_Vegetation.rpf", img: "../assets/Extra.png", url: "http://213.199.63.97/CA_Vegetation.rpf" },
                { name: "Extra Vegetation", file: "CA_Extra_Vegetation.rpf", img: "../assets/Extra.png", url: "http://213.199.63.97/CA_Extra_Vegetation.rpf" },
                { name: "Sandy Shores Vegetation", file: "CA_Sandy_Shores_Vegetation.rpf", img: "../assets/Sandy.png", url: "http://213.199.63.97/CA_Sandy_Shores_Vegetation.rpf" }
            ]
        },
        {
            title: "Addons",
            subtitle: "تحتاج النسخة الثانية أو الثالثة",
            icon: `<svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="3" width="5" height="5"/><rect x="10" y="3" width="5" height="5"/><rect x="3" y="10" width="5" height="5"/><rect x="10" y="10" width="5" height="5"/></svg>`,
            requiredPlans: ["CA-2", "CA-3", "CA-4"],
            mods: [
                { name: "Halloween Content Pack", file: "CA_Halloween_Pack.rpf", img: "../assets/Halloween Content Pack.jpg", url: "http://213.199.63.97/CA_Halloween_Pack.rpf" },
                { name: "Christmas Content Pack", file: "CA_Christmas_Pack.rpf", img: "../assets/Christmas Content Pack.jpg", url: "http://213.199.63.97/CA_Christmas_Pack.rpf" },
                { name: "Weather FOGGY", file: "CA_Foggy.rpf", img: "../assets/Foggy_Deep Weather.jpg", url: "http://213.199.63.97/CA_Foggy.rpf" },
                { name: "Volumetric Clouds", file: "CA_Volumetric_Clouds.rpf", img: "../assets/vol.png", url: "http://213.199.63.97/CA_Volumetric_Clouds.rpf" },
                { name: "Snowy Mount Chiliad", file: "CA_Snowy_Mount_Chilliad.rpf", img: "../assets/Mount.png", url: "http://213.199.63.97/CA_Snowy_Mount_Chilliad.rpf" }
            ]
        }
    ];
    res.json({ success: true, sections });
});
app.listen(process.env.PORT || 3000, () => console.log("✅ Backend running"));