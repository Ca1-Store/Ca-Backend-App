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
};

db.query(`
    CREATE TABLE IF NOT EXISTS users (
        discord_id TEXT PRIMARY KEY,
        hwid TEXT,
        last_login TIMESTAMP
    )
`).catch(err => console.error("DB init error:", err));

/* ============================================================
   helper: جيب النسخة الحالية من Discord مباشرة
============================================================ */
async function getPlanFromDiscord(discordId) {
    const memberRes = await fetch(
        `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${discordId}`,
        { headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` } }
    );
    const member = await memberRes.json();

    if (!member.roles) return null;

    const planPriority = ["CA-3", "CA-2", "CA-1"];

    for (const p of planPriority) {
        const roleId = Object.keys(ROLE_PLAN_MAP).find(k => ROLE_PLAN_MAP[k] === p);
        if (roleId && member.roles.includes(roleId)) return p;
    }

    return null;
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

        // جيب النسخة من Discord
        const plan = await getPlanFromDiscord(discordId);

        if (!plan) return res.json({ success: false, message: "ما عندك نسخة فعّالة في السيرفر" });

        const token = jwt.sign(
            { discordId, plan, hwid },
            JWT_SECRET,
            { expiresIn: "30d" }
        );

        await db.query("UPDATE users SET last_login=NOW() WHERE discord_id=$1", [discordId]);

        return res.json({ success: true, token, plan, username: user.username });

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

        // تحقق من الرول الحالي في Discord - فوري وليس من الـ token
        const plan = await getPlanFromDiscord(decoded.discordId);

        if (!plan) {
            return res.json({ success: false, message: "انتهت صلاحية نسختك أو تم إلغاؤها" });
        }

        return res.json({ success: true, plan, discordId: decoded.discordId });

    } catch {
        return res.json({ success: false, message: "Token منتهي أو غير صالح" });
    }
});

app.listen(process.env.PORT || 3000, () => console.log("✅ Backend running"));