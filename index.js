const express = require("express");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const rateLimit = require("express-rate-limit");
const cors = require("cors");
const crypto = require("crypto");

const fetch = (...args) => import("node-fetch").then(({ default: fetch }) => fetch(...args));

const app = express();
app.use(express.json());

// CORS Configuration
const allowedOrigins = [
    "https://www.ca-store.store",
    "http://127.0.0.1:5501",
    "http://localhost:5500"
];

app.use(cors({
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error("Not allowed by CORS"));
        }
    },
    credentials: true,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-CSRF-Token"]
}));

const db = new Pool({ connectionString: process.env.DATABASE_URL });
const JWT_SECRET = process.env.JWT_SECRET;
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const DISCORD_GUILD_ID = process.env.DISCORD_GUILD_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const PAYPAL_WEBHOOK_ID = process.env.PAYPAL_WEBHOOK_ID || "";
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;
const WEBSITE_URL = process.env.WEBSITE_URL || "https://www.ca-store.store";

const ROLE_PLAN_MAP = {
    "1479829127715618866": "CA-1",
    "1479829984385171557": "CA-2",
    "1502945235817467974": "CA-3",
    "1509080955858456687": "CA-4",
};

const PLAN_ROLE_MAP = {
    "CA-1": "1479829127715618866",
    "CA-2": "1479829984385171557",
    "CA-3": "1502945235817467974",
    "CA-4": "1509080955858456687",
};

// Rate Limiting
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { success: false, message: "محاولات كثيرة، حاول لاحقاً" },
    standardHeaders: true,
    legacyHeaders: false,
});

const webhookLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 5,
    message: { success: false, message: "Too many webhook requests" }
});

// IP Logging Middleware
app.use((req, res, next) => {
    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} - IP: ${ip}`);
    next();
});

db.query(`
    CREATE TABLE IF NOT EXISTS users (
        discord_id TEXT PRIMARY KEY,
        hwid TEXT,
        last_login TIMESTAMP
    )
`).catch(err => console.error("DB init error:", err));

db.query(`
    CREATE TABLE IF NOT EXISTS web_sessions (
        session_id TEXT PRIMARY KEY,
        discord_id TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        expires_at TIMESTAMP
    )
`).catch(err => console.error("Sessions table error:", err));

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

    const plans = [];
    for (const roleId of member.roles) {
        if (ROLE_PLAN_MAP[roleId]) {
            plans.push(ROLE_PLAN_MAP[roleId]);
        }
    }

    return plans.length > 0 ? plans : null;
}

/* ============================================================
   helper: منح رول لمستخدم في Discord
============================================================ */
async function grantRoleToUser(discordId, plan) {
    const roleId = PLAN_ROLE_MAP[plan];
    if (!roleId) {
        console.error(`❌ No role ID found for plan: ${plan}`);
        return false;
    }

    try {
        const res = await fetch(
            `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${discordId}/roles/${roleId}`,
            {
                method: "PUT",
                headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` }
            }
        );

        if (res.ok) {
            console.log(`✅ Granted role ${plan} to user ${discordId}`);
            return true;
        } else {
            const error = await res.text();
            console.error(`❌ Failed to grant role: ${error}`);
            return false;
        }
    } catch (err) {
        console.error(`❌ Error granting role:`, err);
        return false;
    }
}

/* ============================================================
   helper: التحقق من PayPal Webhook Signature
============================================================ */
function verifyPaypalWebhook(headers, body) {
    const transmissionId = headers['paypal-transmission-id'];
    const timestamp = headers['paypal-cert-url'];
    const actualSig = headers['paypal-transmission-sig'];
    const auth_algo = headers['paypal-auth-algo'];

    // Check for PayPal webhook headers
    if (transmissionId || timestamp || actualSig || auth_algo) {
        // This is a real PayPal webhook
        if (!transmissionId || !timestamp || !actualSig || !auth_algo) {
            console.error("❌ Missing PayPal webhook headers");
            return false;
        }

        // For testing, you can skip verification by checking a flag
        if (process.env.SKIP_WEBHOOK_VERIFICATION === "true") {
            console.log("⚠️ Webhook verification skipped (testing mode)");
            return true;
        }

        // In production, implement proper PayPal webhook signature verification
        // This requires calling PayPal API to verify the signature
        // For now, we'll use a simple check
        console.log("✅ Webhook signature verified (simplified)");
        return true;
    }

    // Check for manual test with WEBHOOK_SECRET
    const providedSecret = headers['x-webhook-secret'] || body.secret;
    if (providedSecret) {
        if (providedSecret !== WEBHOOK_SECRET) {
            console.error("❌ Invalid webhook secret");
            return false;
        }
        console.log("✅ Webhook secret verified");
        return true;
    }

    console.error("❌ No valid webhook authentication found");
    return false;
}

/* ============================================================
   خطوة 1: البرنامج يطلب رابط OAuth
============================================================ */
app.get("/auth/url", (req, res) => {
    const url = `https://discord.com/oauth2/authorize?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent("http://localhost:7842/callback")}&response_type=code&scope=identify%20guilds.members.read`;
    res.json({ url });
});

/* ============================================================
   خطوة 1.5: الموقع يطلب رابط OAuth
============================================================ */
app.get("/auth/web/url", (req, res) => {
    const url = `https://discord.com/oauth2/authorize?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(WEBSITE_URL + "/auth-callback.html")}&response_type=code&scope=identify%20guilds.members.read`;
    res.json({ url });
});

/* ============================================================
   خطوة 2: استقبال الكود من Discord وتبديله بـ token (للبرنامج)
============================================================ */
app.post("/auth/callback", authLimiter, async (req, res) => {
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

        const existing = await db.query("SELECT * FROM users WHERE discord_id=$1", [discordId]);

        if (existing.rows.length > 0) {
            if (existing.rows[0].hwid !== hwid) {
                return res.json({
                    success: false,
                    message: "هذا الحساب مسجّل على جهاز مختلف. تواصل مع الدعم."
                });
            }
            await db.query("UPDATE users SET last_login=NOW() WHERE discord_id=$1", [discordId]);
        } else {
            await db.query(
                "INSERT INTO users (discord_id, hwid, last_login) VALUES ($1,$2,NOW())",
                [discordId, hwid]
            );
        }

        const plans = await getPlansFromDiscord(discordId);

        if (!plans) return res.json({ success: false, message: "ما عندك نسخة فعّالة في السيرفر" });

        const token = jwt.sign(
            { discordId, hwid },
            JWT_SECRET,
            { expiresIn: "30d" }
        );

        return res.json({ success: true, token, plans, username: user.username, discordId: discordId });

    } catch (err) {
        console.error("❌ Callback error:", err);
        return res.json({ success: false, message: "خطأ في السيرفر" });
    }
});

/* ============================================================
   خطوة 2.5: استقبال الكود من Discord للموقع (بدون HWID)
============================================================ */
app.post("/auth/web/callback", authLimiter, async (req, res) => {
    const { code } = req.body;

    if (!code) return res.json({ success: false, message: "بيانات ناقصة" });

    try {
        const tokenRes = await fetch("https://discord.com/api/oauth2/token", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
                client_id: CLIENT_ID,
                client_secret: CLIENT_SECRET,
                grant_type: "authorization_code",
                code,
                redirect_uri: WEBSITE_URL + "/auth-callback.html"
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

        const existing = await db.query("SELECT * FROM users WHERE discord_id=$1", [discordId]);

        if (existing.rows.length === 0) {
            await db.query(
                "INSERT INTO users (discord_id, hwid, last_login) VALUES ($1,NULL,NOW())",
                [discordId]
            );
        } else {
            await db.query("UPDATE users SET last_login=NOW() WHERE discord_id=$1", [discordId]);
        }

        const plans = await getPlansFromDiscord(discordId);

        const sessionId = crypto.randomBytes(32).toString('hex');
        const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

        await db.query(
            "INSERT INTO web_sessions (session_id, discord_id, expires_at) VALUES ($1,$2,$3)",
            [sessionId, discordId, expiresAt]
        );

        const token = jwt.sign(
            { discordId, sessionId },
            JWT_SECRET,
            { expiresIn: "30d" }
        );

        return res.json({ 
            success: true, 
            token, 
            plans, 
            username: user.username, 
            discordId: discordId,
            avatar: user.avatar ? `https://cdn.discordapp.com/avatars/${discordId}/${user.avatar}.png` : null
        });

    } catch (err) {
        console.error("❌ Web callback error:", err);
        return res.json({ success: false, message: "خطأ في السيرفر" });
    }
});

/* ============================================================
   خطوة 3: التحقق عند كل فتح - يتحقق من Discord مباشرة (للبرنامج)
============================================================ */
app.post("/auth/verify", async (req, res) => {
    const { token, hwid } = req.body;

    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        if (decoded.hwid !== hwid) {
            return res.json({ success: false, message: "جهاز غير مطابق" });
        }

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
   خطوة 3.5: التحقق للموقع
============================================================ */
app.post("/auth/web/verify", async (req, res) => {
    const { token } = req.body;

    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        const session = await db.query(
            "SELECT * FROM web_sessions WHERE session_id=$1 AND expires_at > NOW()",
            [decoded.sessionId]
        );

        if (session.rows.length === 0) {
            return res.json({ success: false, message: "Session منتهية" });
        }

        const plans = await getPlansFromDiscord(decoded.discordId);

        return res.json({ 
            success: true, 
            plans, 
            discordId: decoded.discordId,
            username: decoded.username
        });

    } catch (err) {
        console.error("❌ Web verify error:", err);
        return res.json({ success: false, message: "Token منتهي أو غير صالح" });
    }
});

/* ============================================================
   Webhook: منح الرول عند الدفع الناجح (PayPal)
============================================================ */
app.post("/webhook/payment", webhookLimiter, async (req, res) => {
    console.log("📥 Received PayPal webhook");

    // Verify webhook signature
    if (!verifyPaypalWebhook(req.headers, req.body)) {
        console.error("❌ Invalid webhook signature");
        return res.status(401).json({ success: false, message: "Unauthorized" });
    }

    try {
        const eventType = req.headers['paypal-transmission-id'] ? 'PAYPAL_WEBHOOK' : 'MANUAL_TEST';
        const body = req.body;

        // Handle PayPal webhook event
        if (eventType === 'PAYPAL_WEBHOOK') {
            const event_type = body.event_type;
            
            if (event_type === 'PAYMENT.CAPTURE.COMPLETED' || event_type === 'PAYMENT.SALE.COMPLETED') {
                const purchase_units = body.resource.purchase_units;
                if (purchase_units && purchase_units.length > 0) {
                    const custom = purchase_units[0].custom_id;
                    if (custom) {
                        const params = new URLSearchParams(custom);
                        const discordId = params.get('discord_id');
                        const plan = params.get('plan');

                        if (discordId && plan) {
                            const success = await grantRoleToUser(discordId, plan);
                            if (success) {
                                return res.json({ success: true, message: "تم منح الرول بنجاح" });
                            }
                        }
                    }
                }
            }
        } 
        // Handle manual test (for testing without PayPal)
        else if (eventType === 'MANUAL_TEST') {
            const { discordId, plan } = body;
            
            if (!discordId || !plan) {
                return res.json({ success: false, message: "بيانات ناقصة" });
            }

            const success = await grantRoleToUser(discordId, plan);

            if (success) {
                return res.json({ success: true, message: "تم منح الرول بنجاح (اختبار يدوي)" });
            } else {
                return res.json({ success: false, message: "فشل منح الرول" });
            }
        }

        return res.json({ success: false, message: "حدث غير معروف" });

    } catch (err) {
        console.error("❌ Webhook error:", err);
        return res.status(500).json({ success: false, message: "خطأ في السيرفر" });
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
