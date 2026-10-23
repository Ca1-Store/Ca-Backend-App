const express = require("express");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const rateLimit = require("express-rate-limit");
const cors = require("cors");
const crypto = require("crypto");

// Node 18+ فيه fetch مدمج، ويرجع لـ node-fetch فقط إذا كان Node قديماً
const fetch = (...args) => (typeof globalThis.fetch === "function" ? globalThis.fetch(...args) : import("node-fetch").then(({ default: f }) => f(...args)));

const app = express();
app.set('trust proxy', 1);
app.use(express.json());

// CORS Configuration
const allowedOrigins = [
    "https://www.ca-store.store",
    "http://127.0.0.1:5501",
    "http://localhost:5500",
    "https://admin-panel-orcin-zeta.vercel.app",
    "https://admin-panel-puce-five.vercel.app",
    "https://admin-panel-henna-mu.vercel.app",
    "https://ca-store.store",
    ...((process.env.EXTRA_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean))
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
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-CSRF-Token", "x-webhook-secret"]
}));

const db = new Pool({ connectionString: process.env.DATABASE_URL });
const JWT_SECRET = process.env.JWT_SECRET;
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const DISCORD_GUILD_ID = process.env.DISCORD_GUILD_ID;
const DISCORD_LOGS_CHANNEL_ID = process.env.DISCORD_LOGS_CHANNEL_ID || "";
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const PAYPAL_WEBHOOK_ID = process.env.PAYPAL_WEBHOOK_ID || "";
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;
const WEBSITE_URL = process.env.WEBSITE_URL || "https://www.ca-store.store";
const ADMIN_SECRET = process.env.ADMIN_SECRET || "Admina091235239";
const ADMIN_DISCORD_ID = "1336347875206234292";

const ROLE_PLAN_MAP = {
    "1479829127715618866": "CA-1",
    "1479829984385171557": "CA-2",
    "1502945235817467974": "CA-3",
    "1509080955858456687": "CA-4",
    "1518902435421225121": "CA-5",
};

const PLAN_ROLE_MAP = {
    "CA-1": "1479829127715618866",
    "CA-2": "1479829984385171557",
    "CA-3": "1502945235817467974",
    "CA-4": "1509080955858456687",
    "CA-5": "1518902435421225121",
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

const ratingsLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 10,
    message: { success: false, message: "Too many rating requests" }
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
   RATINGS & COMMENTS TABLES
============================================================ */
db.query(`
    CREATE TABLE IF NOT EXISTS ratings (
        id SERIAL PRIMARY KEY,
        pack_id TEXT NOT NULL,
        rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
        username TEXT NOT NULL,
        discord_id TEXT,
        created_at TIMESTAMP DEFAULT NOW()
    )
`).catch(err => console.error("Ratings table error:", err));

db.query(`
    CREATE TABLE IF NOT EXISTS comments (
        id SERIAL PRIMARY KEY,
        pack_id TEXT NOT NULL,
        comment TEXT NOT NULL,
        rating INTEGER CHECK (rating >= 1 AND rating <= 5),
        username TEXT NOT NULL,
        discord_id TEXT,
        created_at TIMESTAMP DEFAULT NOW()
    )
`).catch(err => console.error("Comments table error:", err));

// Create indexes for performance
db.query(`CREATE INDEX IF NOT EXISTS idx_ratings_pack_id ON ratings(pack_id)`)
    .catch(err => console.error("Index error:", err));
db.query(`CREATE INDEX IF NOT EXISTS idx_comments_pack_id ON comments(pack_id)`)
    .catch(err => console.error("Index error:", err));

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
   helper: إرسال رسالة DM للمستخدم في Discord
============================================================ */
async function sendDMToUser(discordId, plan) {
    try {
        const dmRes = await fetch(
            `https://discord.com/api/users/@me/channels`,
            {
                method: "POST",
                headers: {
                    "Authorization": `Bot ${DISCORD_BOT_TOKEN}`,
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    recipient_id: discordId
                })
            }
        );

        if (!dmRes.ok) {
            console.error("❌ Failed to create DM channel");
            return false;
        }

        const dmData = await dmRes.json();
        const channelId = dmData.id;

        const message = `🎉 **تم الدفع بنجاح!**

تم منح رتبة **${plan}** لحسابك في Discord.

📥 **كيفية تنزيل الجرافيكس:**

1. حمل البرنامج
2. سجل الدخول بحسابك
3. اذهب إلى صفحة "نسخ الجرافيكس"
4. اختر النسخة التي اشتريتها
5. وشاهد المقطع اللي موجود بروم طريقة الاستخدام

💡 **ملاحظة:** إذا واجهت أي مشكلة، افتح تذكرة في سيرفر Discord.

شكراً لشرائك من CA Store! 🚀`;

        const msgRes = await fetch(
            `https://discord.com/api/channels/${channelId}/messages`,
            {
                method: "POST",
                headers: {
                    "Authorization": `Bot ${DISCORD_BOT_TOKEN}`,
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    content: message
                })
            }
        );

        if (msgRes.ok) {
            console.log(`✅ Sent DM to user ${discordId}`);
            return true;
        } else {
            const error = await msgRes.text();
            console.error(`❌ Failed to send DM: ${error}`);
            return false;
        }
    } catch (err) {
        console.error(`❌ Error sending DM:`, err);
        return false;
    }
}

/* ============================================================
   helper: إرسال رسالة إلى روم السجلات في Discord
============================================================ */
async function sendLogToDiscord(discordId, plan, amount, paymentMethod) {
    if (!DISCORD_LOGS_CHANNEL_ID) {
        console.warn("⚠️ DISCORD_LOGS_CHANNEL_ID not configured");
        return false;
    }

    try {
        const userRes = await fetch(
            `https://discord.com/api/users/${discordId}`,
            { headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` } }
        );
        const user = await userRes.json();

        const username = user.username || "Unknown";
        const avatar = user.avatar ? `https://cdn.discordapp.com/avatars/${discordId}/${user.avatar}.png` : null;

        const embed = {
            title: "🛒 عملية شراء جديدة",
            color: 5763719,
            fields: [
                {
                    name: "👤 حساب Discord",
                    value: `<@${discordId}> (${username})`,
                    inline: true
                },
                {
                    name: "📦 المنتج",
                    value: plan,
                    inline: true
                },
                {
                    name: "💰 المبلغ",
                    value: amount + " USD",
                    inline: true
                },
                {
                    name: "💳 طريقة الدفع",
                    value: paymentMethod,
                    inline: true
                },
                {
                    name: "📅 التاريخ",
                    value: new Date().toLocaleString("ar-SA"),
                    inline: true
                }
            ],
            footer: {
                text: "CA Store - نظام الشراء الآلي"
            },
            timestamp: new Date().toISOString()
        };

        const msgRes = await fetch(
            `https://discord.com/api/channels/${DISCORD_LOGS_CHANNEL_ID}/messages`,
            {
                method: "POST",
                headers: {
                    "Authorization": `Bot ${DISCORD_BOT_TOKEN}`,
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    embeds: [embed]
                })
            }
        );

        if (msgRes.ok) {
            console.log(`✅ Sent log to Discord channel`);
            return true;
        } else {
            const error = await msgRes.text();
            console.error(`❌ Failed to send log: ${error}`);
            return false;
        }
    } catch (err) {
        console.error(`❌ Error sending log:`, err);
        return false;
    }
}

/* ============================================================
   helper: التحقق من PayPal Webhook Signature (محسّن)
============================================================ */
async function verifyPaypalWebhook(headers, body) {
    const transmissionId = headers['paypal-transmission-id'];
    const timestamp = headers['paypal-cert-url'];
    const actualSig = headers['paypal-transmission-sig'];
    const auth_algo = headers['paypal-auth-algo'];

    if (transmissionId || timestamp || actualSig || auth_algo) {
        if (!transmissionId || !timestamp || !actualSig || !auth_algo) {
            console.error("❌ Missing PayPal webhook headers");
            return false;
        }

        if (process.env.SKIP_WEBHOOK_VERIFICATION === "true") {
            console.log("⚠️ Webhook verification skipped (testing mode)");
            return true;
        }

        try {
            const verifyUrl = `https://api-m.paypal.com/v1/notifications/verify-webhook-signature`;
            
            const verifyBody = {
                auth_algo: auth_algo,
                cert_url: timestamp,
                transmission_id: transmissionId,
                transmission_sig: actualSig,
                transmission_time: headers['paypal-transmission-time'],
                webhook_id: PAYPAL_WEBHOOK_ID,
                webhook_event: body
            };

            const verifyRes = await fetch(verifyUrl, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Basic ${Buffer.from(CLIENT_ID + ":" + CLIENT_SECRET).toString('base64')}` 
                },
                body: JSON.stringify(verifyBody)
            });

            const verifyData = await verifyRes.json();

            if (verifyData.verification_status === "SUCCESS") {
                console.log("✅ PayPal webhook signature verified successfully");
                return true;
            } else {
                console.error("❌ PayPal webhook signature verification failed:", verifyData);
                return false;
            }
        } catch (err) {
            console.error("❌ Error verifying PayPal webhook signature:", err);
            return false;
        }
    }

    const providedSecret = body.secret;
    if (providedSecret) {
        if (!WEBHOOK_SECRET) {
            console.error("❌ WEBHOOK_SECRET not configured");
            return false;
        }
        
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
    const redirectUri = req.query.redirect_uri || (WEBSITE_URL + "/auth-callback.html");
    const url = `https://discord.com/oauth2/authorize?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=identify%20guilds.members.read`;
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
            if (existing.rows[0].hwid !== null && existing.rows[0].hwid !== hwid) {
                return res.json({
                    success: false,
                    message: "هذا الحساب مسجّل على جهاز مختلف. تواصل مع الدعم."
                });
            }
            if (existing.rows[0].hwid === null) {
                await db.query("UPDATE users SET hwid=$1, last_login=NOW() WHERE discord_id=$2", [hwid, discordId]);
            } else {
                await db.query("UPDATE users SET last_login=NOW() WHERE discord_id=$1", [discordId]);
            }
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
        if (!discordId) { console.error("❌ web login: Discord user fetch failed:", JSON.stringify(user)); return res.json({ success: false, message: "تعذّر قراءة بيانات حسابك من ديسكورد" }); }

        // تسجيل المستخدم وجلسة الموقع: غير حرجين، فشلهما لا يمنع تسجيل الدخول
        try {
            const existing = await db.query("SELECT 1 FROM users WHERE discord_id=$1", [discordId]);
            if (existing.rows.length === 0) await db.query("INSERT INTO users (discord_id, last_login) VALUES ($1,NOW())", [discordId]);
            else await db.query("UPDATE users SET last_login=NOW() WHERE discord_id=$1", [discordId]);
        } catch (e) { console.error("⚠️ web login: users table error:", e.message); }

        let plans = null;
        try { plans = await getPlansFromDiscord(discordId); } catch (e) { console.error("⚠️ web login: roles lookup error:", e.message); }

        let sessionId;
        try {
            sessionId = crypto.randomBytes(32).toString('hex');
            const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
            await db.query("INSERT INTO web_sessions (session_id, discord_id, expires_at) VALUES ($1,$2,$3)", [sessionId, discordId, expiresAt]);
        } catch (e) { console.error("⚠️ web login: web_sessions error:", e.message); sessionId = undefined; }

        const token = jwt.sign(
            sessionId ? { discordId, sessionId } : { discordId },
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
        console.error("❌ Web callback error:", err && err.message, err && err.stack);
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
   ADMIN API: إعادة تعيين جهاز مستخدم (للأدمن فقط)
============================================================ */
app.post("/admin/reset-device", async (req, res) => {
    const { adminSecret, discordId, newHwid } = req.body;

    if (!adminSecret || !discordId || !newHwid) {
        return res.json({ success: false, message: "بيانات ناقصة" });
    }

    if (adminSecret !== ADMIN_SECRET) {
        return res.json({ success: false, message: "غير مصرح" });
    }

    try {
        await db.query(
            "UPDATE users SET hwid=$1, last_login=NOW() WHERE discord_id=$2",
            [newHwid, discordId]
        );

        console.log(`✅ Admin reset device for user ${discordId} to ${newHwid}`);

        return res.json({ 
            success: true, 
            message: "تم تحديث الجهاز بنجاح"
        });

    } catch (err) {
        console.error("❌ Admin reset device error:", err);
        return res.json({ success: false, message: "خطأ في السيرفر" });
    }
});

/* ============================================================
   ADMIN API: حذف جهاز مستخدم (للأدمن فقط)
============================================================ */
app.post("/admin/remove-device", async (req, res) => {
    const { adminSecret, discordId } = req.body;

    if (!adminSecret || !discordId) {
        return res.json({ success: false, message: "بيانات ناقصة" });
    }

    if (adminSecret !== ADMIN_SECRET) {
        return res.json({ success: false, message: "غير مصرح" });
    }

    try {
        await db.query(
            "UPDATE users SET hwid=NULL WHERE discord_id=$1",
            [discordId]
        );

        console.log(`✅ Admin removed device for user ${discordId}`);

        return res.json({ 
            success: true, 
            message: "تم حذف الجهاز بنجاح"
        });

    } catch (err) {
        console.error("❌ Admin remove device error:", err);
        return res.json({ success: false, message: "خطأ في السيرفر" });
    }
});

/* ============================================================
   ADMIN API: عرض جميع المستخدمين وأجهزتهم (للأدمن فقط)
============================================================ */
app.post("/admin/list-users", async (req, res) => {
    const { adminSecret } = req.body;

    if (!adminSecret) {
        return res.json({ success: false, message: "بيانات ناقصة" });
    }

    if (adminSecret !== ADMIN_SECRET) {
        return res.json({ success: false, message: "غير مصرح" });
    }

    try {
        const users = await db.query(
            "SELECT discord_id, hwid, last_login FROM users ORDER BY last_login DESC"
        );

        return res.json({ 
            success: true, 
            users: users.rows
        });

    } catch (err) {
        console.error("❌ Admin list users error:", err);
        return res.json({ success: false, message: "خطأ في السيرفر" });
    }
});

/* ============================================================
   Webhook: منح الرول عند الدفع الناجح (PayPal)
============================================================ */
app.post("/webhook/payment", webhookLimiter, async (req, res) => {
    console.log("📥 Received PayPal webhook");

    const isValid = await verifyPaypalWebhook(req.headers, req.body);
    if (!isValid) {
        console.error("❌ Invalid webhook signature");
        return res.status(401).json({ success: false, message: "Unauthorized" });
    }

    try {
        const eventType = req.headers['paypal-transmission-id'] ? 'PAYPAL_WEBHOOK' : 'MANUAL_TEST';
        const body = req.body;

        if (eventType === 'PAYPAL_WEBHOOK') {
            const event_type = body.event_type;
            
            console.log(`📋 Event type: ${event_type}`);
            
            if (event_type === 'PAYMENT.CAPTURE.COMPLETED' || event_type === 'PAYMENT.SALE.COMPLETED') {
                const purchase_units = body.resource.purchase_units;
                console.log(`📦 Purchase units:`, JSON.stringify(purchase_units));
                
                if (purchase_units && purchase_units.length > 0) {
                    const custom = purchase_units[0].custom_id;
                    console.log(`🔑 Custom ID: ${custom}`);
                    
                    if (custom) {
                        const params = new URLSearchParams(custom);
                        const discordId = params.get('discord_id');
                        const plan = params.get('plan');
                        
                        console.log(`👤 Discord ID: ${discordId}`);
                        console.log(`📋 Plan: ${plan}`);

                        if (discordId && plan) {
                            const amount = purchase_units[0].amount.value;
                            const paymentMethod = "PayPal";
                            
                            const roleSuccess = await grantRoleToUser(discordId, plan);
                            if (roleSuccess) recordPurchase(discordId, plan, amount, paymentMethod);
                            const dmSuccess = await sendDMToUser(discordId, plan);
                            const logSuccess = await sendLogToDiscord(discordId, plan, amount, paymentMethod);
                            
                            if (roleSuccess && dmSuccess && logSuccess) {
                                console.log(`✅ Successfully granted role, sent DM, and logged to Discord for ${discordId}`);
                                return res.json({ success: true, message: "تم منح الرول وإرسال الرسالة وتسجيل العملية بنجاح" });
                            } else if (roleSuccess && dmSuccess) {
                                console.log(`⚠️ Granted role and sent DM but failed to log for ${discordId}`);
                                return res.json({ success: true, message: "تم منح الرول وإرسال الرسالة بنجاح (فشل التسجيل)" });
                            } else if (roleSuccess) {
                                console.log(`⚠️ Granted role but failed to send DM and log for ${discordId}`);
                                return res.json({ success: true, message: "تم منح الرول بنجاح (فشل إرسال الرسالة والتسجيل)" });
                            } else {
                                console.log(`❌ Failed to grant role to ${discordId}`);
                                return res.json({ success: false, message: "فشل منح الرول" });
                            }
                        } else {
                            console.error(`❌ Missing discord_id or plan in custom_id`);
                            return res.json({ success: false, message: "بيانات ناقصة في custom_id" });
                        }
                    } else {
                        console.error(`❌ No custom_id found in purchase_units`);
                        return res.json({ success: false, message: "لا يوجد custom_id" });
                    }
                } else {
                    console.error(`❌ No purchase_units found`);
                    return res.json({ success: false, message: "لا يوجد purchase_units" });
                }
            } else {
                console.log(`ℹ️ Ignoring event type: ${event_type}`);
                return res.json({ success: true, message: "تم استقبال الحدث" });
            }
        } 
        else if (eventType === 'MANUAL_TEST') {
            const { discordId, plan } = body;
            
            if (!discordId || !plan) {
                return res.json({ success: false, message: "بيانات ناقصة" });
            }

            const roleSuccess = await grantRoleToUser(discordId, plan);
            if (roleSuccess) recordPurchase(discordId, plan, "0.00", "Manual Test");
            const dmSuccess = await sendDMToUser(discordId, plan);
            const logSuccess = await sendLogToDiscord(discordId, plan, "0.00", "Manual Test");

            if (roleSuccess && dmSuccess && logSuccess) {
                return res.json({ success: true, message: "تم منح الرول وإرسال الرسالة وتسجيل العملية بنجاح (اختبار يدوي)" });
            } else if (roleSuccess && dmSuccess) {
                return res.json({ success: true, message: "تم منح الرول وإرسال الرسالة بنجاح (فشل التسجيل) - اختبار يدوي" });
            } else if (roleSuccess) {
                return res.json({ success: true, message: "تم منح الرول بنجاح (فشل إرسال الرسالة والتسجيل) - اختبار يدوي" });
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
   RATINGS API - نظام التقييمات الأونلاين
============================================================ */

/* ============================================================
   GET /api/ratings - جلب جميع التقييمات
============================================================ */
app.get("/api/ratings", async (req, res) => {
    try {
        const result = await db.query(`
            SELECT pack_id, 
                   AVG(rating) as average_rating, 
                   COUNT(*) as total_ratings
            FROM ratings
            GROUP BY pack_id
        `);

        const ratings = {};
        for (const row of result.rows) {
            ratings[row.pack_id] = {
                averageRating: parseFloat(row.average_rating).toFixed(1),
                totalRatings: parseInt(row.total_ratings)
            };
        }

        res.json({ success: true, ratings });
    } catch (err) {
        console.error("Error fetching ratings:", err);
        res.status(500).json({ success: false, message: "خطأ في جلب التقييمات" });
    }
});

/* ============================================================
   GET /api/ratings/:packId - جلب تقييمات باك معين
============================================================ */
app.get("/api/ratings/:packId", async (req, res) => {
    const { packId } = req.params;

    try {
        // جلب التقييمات
        const ratingsResult = await db.query(
            "SELECT * FROM ratings WHERE pack_id = $1 ORDER BY created_at DESC",
            [packId]
        );

        // جلب التعليقات
        const commentsResult = await db.query(
            "SELECT * FROM comments WHERE pack_id = $1 ORDER BY created_at DESC",
            [packId]
        );

        // حساب المتوسط
        let averageRating = 0;
        if (ratingsResult.rows.length > 0) {
            const sum = ratingsResult.rows.reduce((acc, r) => acc + r.rating, 0);
            averageRating = (sum / ratingsResult.rows.length).toFixed(1);
        }

        res.json({
            success: true,
            ratings: ratingsResult.rows,
            comments: commentsResult.rows,
            averageRating: parseFloat(averageRating),
            totalRatings: ratingsResult.rows.length
        });
    } catch (err) {
        console.error("Error fetching pack ratings:", err);
        res.status(500).json({ success: false, message: "خطأ في جلب تقييمات الباك" });
    }
});

/* ============================================================
   POST /api/ratings - إرسال تقييم جديد
============================================================ */
app.post("/api/ratings", ratingsLimiter, async (req, res) => {
    const { packId, rating, comment, username, discordId } = req.body;

    if (!packId || !rating || !username) {
        return res.json({ success: false, message: "بيانات ناقصة" });
    }

    if (rating < 1 || rating > 5) {
        return res.json({ success: false, message: "التقييم يجب أن يكون بين 1 و 5" });
    }

    try {
        // إضافة التقييم
        await db.query(
            "INSERT INTO ratings (pack_id, rating, username, discord_id) VALUES ($1, $2, $3, $4)",
            [packId, rating, username, discordId || null]
        );

        // إضافة التعليق إذا وجد
        if (comment && comment.trim()) {
            await db.query(
                "INSERT INTO comments (pack_id, comment, rating, username, discord_id) VALUES ($1, $2, $3, $4, $5)",
                [packId, comment.trim(), rating, username, discordId || null]
            );
        }

        // حساب المتوسط الجديد
        const result = await db.query(
            "SELECT AVG(rating) as avg, COUNT(*) as count FROM ratings WHERE pack_id = $1",
            [packId]
        );

        const averageRating = parseFloat(result.rows[0].avg).toFixed(1);
        const totalRatings = parseInt(result.rows[0].count);

        res.json({ 
            success: true, 
            averageRating, 
            totalRatings 
        });
    } catch (err) {
        console.error("Error submitting rating:", err);
        res.status(500).json({ success: false, message: "خطأ في إرسال التقييم" });
    }
});

/* ============================================================
   DELETE /api/ratings/comment - حذف تعليق
============================================================ */
app.delete("/api/ratings/comment", async (req, res) => {
    const { commentId, discordId } = req.body;

    if (!commentId) {
        return res.json({ success: false, message: "بيانات ناقصة" });
    }

    try {
        // التحقق من أن المستخدم هو صاحب التعليق أو أدمن
        const commentResult = await db.query(
            "SELECT * FROM comments WHERE id = $1",
            [commentId]
        );

        if (commentResult.rows.length === 0) {
            return res.json({ success: false, message: "التعليق غير موجود" });
        }

        const comment = commentResult.rows[0];

// السماح بالحذف إذا كان المستخدم هو صاحب التعليق أو أدمن
const isOwner = discordId && comment.discord_id === discordId;
const isAdmin = discordId === ADMIN_DISCORD_ID;

if (!isOwner && !isAdmin) {
    return res.json({ success: false, message: "غير مصرح بحذف هذا التعليق" });
}        await db.query("DELETE FROM comments WHERE id = $1", [commentId]);

        res.json({ success: true, message: "تم حذف التعليق بنجاح" });
    } catch (err) {
        console.error("Error deleting comment:", err);
        res.status(500).json({ success: false, message: "خطأ في حذف التعليق" });
    }
});

/* ============================================================
   DELETE /api/ratings/rating - حذف تقييم
============================================================ */
app.delete("/api/ratings/rating", async (req, res) => {
    const { ratingId, discordId } = req.body;

    if (!ratingId) {
        return res.json({ success: false, message: "بيانات ناقصة" });
    }

    // فقط الأدمن يقدر يحذف تقييم
    if (discordId !== ADMIN_DISCORD_ID) {
        return res.json({ success: false, message: "غير مصرح بحذف هذا التقييم" });
    }

    try {        // جلب التقييم قبل الحذف لمعرفة pack_id
        const ratingResult = await db.query(
            "SELECT pack_id FROM ratings WHERE id = $1",
            [ratingId]
        );

        if (ratingResult.rows.length === 0) {
            return res.json({ success: false, message: "التقييم غير موجود" });
        }

        const packId = ratingResult.rows[0].pack_id;

        // حذف التقييم
        await db.query("DELETE FROM ratings WHERE id = $1", [ratingId]);

        // حساب المتوسط الجديد
        const result = await db.query(
            "SELECT AVG(rating) as avg, COUNT(*) as count FROM ratings WHERE pack_id = $1",
            [packId]
        );

        const averageRating = result.rows[0].avg ? parseFloat(result.rows[0].avg).toFixed(1) : 0;
        const totalRatings = parseInt(result.rows[0].count);

        res.json({ 
            success: true, 
            message: "تم حذف التقييم بنجاح",
            averageRating,
            totalRatings
        });
    } catch (err) {
        console.error("Error deleting rating:", err);
        res.status(500).json({ success: false, message: "خطأ في حذف التقييم" });
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
            url: "http://169.58.57.199/CA-1%20PACK.zip",
            versions: [
                {
                    version: "1.0",
                    date: "2026-03-18",
                    latest: true,
                    size: "1.80 GB",
                    features: ["الإصدار الأولي", "جرافيكس أساسي"],
                    changelog: "الإصدار الأولي من باك الجرافيكس",
                    url: "http://169.58.57.199/CA-1%20PACK.zip"
                }
            ]
        },
        {
            id: "CA2",
            plan: "CA-2",
            name: "CA - Pack 2",
            level: 2,
            images: ["../assets/Ca-Pack.png", "../assets/Ca-2v2.png", "../assets/Ca_Store.png"],
            url: "http://169.58.57.199/CA-2%20PACK.zip",
            versions: [
                {
                    version: "1.0",
                    date: "2026-05-20",
                    latest: true,
                    size: "276 MB",
                    features: ["جرافيكس محسّن", "أداء أفضل"],
                    changelog: "الإصدار الأولي مع تحسينات على الجرافيكس",
                    url: "http://169.58.57.199/CA-2%20PACK.zip"
                }
            ]
        },
        {
            id: "CA3",
            plan: "CA-3",
            name: "CA - Pack 3",
            level: 3,
            images: ["../assets/ca333.png", "../assets/ca3.png", "../assets/ca33.png"],
            url: "http://169.58.57.199/CA-3%20PACK.zip",
            versions: [
                {
                    version: "1.0",
                    date: "2026-05-25",
                    latest: false,
                    size: "733 MB",
                    features: ["جرافيكس عالي الجودة", "إضاءة محسّنة"],
                    changelog: "الإصدار الأولي مع جرافيكس عالي الجودة",
                    url: "http://169.58.57.199/CA-3%20PACK.zip"
                },
                {
                                    version: "2.0",
                    date: "2026-10-23",
                    latest: true,
                    size: "729 MB",
                    features: ["تحسين الألوان ", "تحسين الشوارع", "تحسين الغيوم"],
                    changelog: "تغييرات بالغيوم وبالسماء وبالالوان لنقل الجرافيكس لجودة أجمل",
                    url: "http://169.58.57.199/CA-3-PACK.v2.zip"
                }

            ]
        },
        {
            id: "CA4",
            plan: "CA-4",
            name: "CA - Pack 4",
            level: 4,
            images: ["../assets/ca444.png", "../assets/ca4.png", "../assets/ca44.png"],
            url: "http://169.58.57.199/CA-4%20PACK.zip",
            versions: [
                {
                    version: "2.0",
                    date: "2026-06-6",
                    latest: true,
                    size: "700 MB",
                    features: ["تخفيف الحجم", "زيادة الفريمات", "أداء محسّن"],
                    changelog: "تحديث رئيسي مع تحسينات كبيرة في الأداء وزيادة الفريمات",
                    url: "http://169.58.57.199/CA-4-PACK-v1.0.1.zip"
                },
                {
                    version: "1.0",
                    date: "2026-05-28",
                    latest: false,
                    size: "900 MB",
                    features: ["الإصدار الأولي", "جرافيكس فائق"],
                    changelog: "الإصدار الأولي من باك الجرافيكس فائق الجودة",
                    url: "http://169.58.57.199/CA-4%20PACK.zip"
                }
            ]
        },
        {
            id: "CA5",
            plan: "CA-5",
            name: "CA - Pack 5",
            level: 5,
            images: ["../assets/CA5.png", "../assets/CA51.png", "../assets/CA52.png"],
            url: "http://169.58.57.199/CA-5%20PACK.zip",
            versions: [
                               {
                    version: "2.0",
                    date: "2026-10-6",
                    latest: true,
                    size: "1.22 GB",
                    features: ["تخفيف الحجم", "ألوان أجمل ", "غيوم أفضل "],
                    changelog: "تحديث رئيسي مع تحسينات كبيرة في الأداء وتحسين الالوان ",
                    url: "http://169.58.57.199/CA-5%20PACK.v2.zip"
                },

                {
                    version: "1.0",
                    date: "2026-06-24",
                    latest: false,
                    size: "1.35 GB",
                    features: ["جرافيكس فائق الجودة", "أداء محسّن"],
                    changelog: "الإصدار الأولي من باك الجرافيكس فائق الجودة",
                    url: "http://169.58.57.199/CA-5%20PACK.zip"
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
        requiredPlans: ["CA-1", "CA-2", "CA-3", "CA-4", "CA-5"],
        mods: [
            { name: "European Roads", file: "European_Roads.rpf", img: "../assets/Europe.png", url: "http://169.58.57.199/European_Roads.rpf" },
            { name: "German Roads", file: "German_Roads.rpf", img: "../assets/German_Roads.png", url: "http://169.58.57.199/German_Roads.rpf" },
            { name: "Ls Roads", file: "Ls_Roads_Pack.rpf", img: "../assets/nve.png", url: "http://169.58.57.199/Ls_Roads_Pack.rpf" },
            { name: "Liberty Roads", file: "Liberty_Roads.rpf", img: "../assets/Liberty.png", url: "http://169.58.57.199/Liberty_Roads.rpf" }
        ]
    },
    {
        title: "Premium Customers",
        subtitle: "للعملاء المميزين",
        icon: `<svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87L18.18 22 12 18.56 5.82 22 7 14.14l-5-4.87 6.91-1.01L12 2z"/></svg>`,
        requiredPlans: ["CA-5"],
        requiredRoles: [
            "1479825414955339947",
            "1509656031427297475"
        ],
        mods: [
            {
                name: "California Roads",
                file: "California_Roads.rpf",
                img: "../assets/California_Roads.png",
                url: "http://169.58.57.199/California_Roads.rpf"
            },
            {
                name: "Forza Roads",
                file: "Forza_Roads.rpf",
                img: "../assets/Forza_Roads.png",
                url: "http://169.58.57.199/Forza_Roads.rpf"
            },
            {
                name: "Monaco Roads",
                file: "Monaco_Roads.rpf",
                img: "../assets/Monaco_Roads.png",
                url: "http://169.58.57.199/Monaco_Roads.rpf"
            },
            {
                name: "San Francisco Roads",
                file: "SanFrancisco_Roads.rpf",
                img: "../assets/SanFrancisco_Roads.png",
                url: "http://169.58.57.199/SanFrancisco_Roads.rpf"
             },
             {
                 name: "Red Vegetation",
                file: "CA_Red_Veget.rpf",
                img: "../assets/Red.png",
                url: "http://169.58.57.199/CA_Red_Veget.rpf"
            },
        ]
    },
    {
        title: "Vegetation",
        subtitle: "تحتاج النسخة الثانية أو الثالثة",
        icon: `<svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 22V12"/><path d="M12 12C12 7 7 4 7 4s0 5 5 8"/><path d="M12 12c0-5 5-8 5-8s0 5-5 8"/></svg>`,
        requiredPlans: ["CA-2", "CA-3", "CA-4", "CA-5"],
        mods: [
            { name: "Vegetation", file: "CA_Vegetation.rpf", img: "../assets/Extra.png", url: "http://169.58.57.199/CA_Vegetation.rpf" },
            { name: "Extra Vegetation", file: "CA_Extra_Vegetation.rpf", img: "../assets/Extra.png", url: "http://169.58.57.199/CA_Extra_Vegetation.rpf" },
            { name: "Sandy Shores Vegetation", file: "CA_Sandy_Shores_Vegetation.rpf", img: "../assets/Sandy.png", url: "http://169.58.57.199/CA_Sandy_Shores_Vegetation.rpf" }
        ]
    },
    {
        title: "Addons",
        subtitle: "تحتاج النسخة الثانية أو الثالثة",
        icon: `<svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="3" width="5" height="5"/><rect x="10" y="3" width="5" height="5"/><rect x="3" y="10" width="5" height="5"/><rect x="10" y="10" width="5" height="5"/></svg>`,
        requiredPlans: ["CA-2", "CA-3", "CA-4", "CA-5"],
        mods: [
            { name: "Halloween Content Pack", file: "CA_Halloween_Pack.rpf", img: "../assets/Halloween Content Pack.jpg", url: "http://169.58.57.199/CA_Halloween_Pack.rpf" },
            { name: "Christmas Content Pack", file: "CA_Christmas_Pack.rpf", img: "../assets/Christmas Content Pack.jpg", url: "http://169.58.57.199/CA_Christmas_Pack.rpf" },
            { name: "Weather FOGGY", file: "CA_Foggy.rpf", img: "../assets/Foggy_Deep Weather.jpg", url: "http://169.58.57.199/CA_Foggy.rpf" },
            { name: "Volumetric Clouds", file: "CA_Volumetric_Clouds.rpf", img: "../assets/vol.png", url: "http://169.58.57.199/CA_Volumetric_Clouds.rpf" },
            { name: "Snowy Mount Chiliad", file: "CA_Snowy_Mount_Chilliad.rpf", img: "../assets/Mount.png", url: "http://169.58.57.199/CA_Snowy_Mount_Chilliad.rpf" }
        ]
    }
];
    res.json({ success: true, sections });
});
/* ============================================================
   API: جلب بيانات Customizations
============================================================ */
app.get("/api/customizations", async (req, res) => {
    const customizationsArray = [
        {
            id: "no_water",
            name: "No Water",
            description: "إزالة الماء من اللعبة لتحسين الأداء والمظهر",
            file: "water.xml",
            destination: "FiveM/FiveM.app/citizen/common/data/levels/gta5",
            url: "http://169.58.57.199/water.xml",
            icon: `<svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 2.69l5.66 5.66a8 8 0 1 1-11.31 0z"/></svg>`,
            warning: "قد يؤثر على بعض السيناريوهات التي تعتمد على الماء"
        },
        {
            id: "no_snow",
            name: "No Snow",
            description: "إزالة الثلج من اللعبة لتحسين الأداء",
            file: "weather.xml",
            destination: "FiveM/FiveM.app/citizen/common/data/levels/gta5",
            url: "http://169.58.57.199/weather.xml",
            icon: `<svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M20 17.58A5 5 0 0 0 18 8h-1.26A8 8 0 1 0 4 16.25"/></svg>`,
            warning: "قد يؤثر على المناخ في بعض السيناريوهات"
        },
        {
            id: "no_mountain",
            name: "No Mountain",
            description: "إزالة جبل تشيلياد لتحسين الأداء",
            file: "no_mountain.rpf",
            destination: "FiveM/FiveM.app/mods",
            url: "http://169.58.57.199/no_mountain.rpf",
            icon: `<svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 2L2 22h20L12 2z"/></svg>`,
            warning: "قد يؤثر على المظهر الجغرافي للعبة"
        },
        {
            id: "no_rain",
            name: "No Rain",
            description: "إزالة المطر لتحسين الأداء",
            file: "no_rain.rpf",
            destination: "FiveM/FiveM.app/mods",
            url: "http://169.58.57.199/no_rain.rpf",
            icon: `<svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M20 16.2A4.5 4.5 0 0 0 17.5 8h-.8a7 7 0 1 0-13.4 0H3a4.5 4.5 0 0 0 0 9h17z"/></svg>`,
            warning: "قد يؤثر على الطقس في بعض السيناريوهات"
        }
    ];
    
    const customizations = {};
    for (const item of customizationsArray) {
        customizations[item.id] = {
            download_url: item.url,
            name: item.name,
            description: item.description,
            file: item.file,
            destination: item.destination,
            icon: item.icon,
            warning: item.warning
        };
    }
    
    res.json({ success: true, customizations });
});

/* ============================================================
   API: مكتبة الفلاتر (ReShade Presets — صيغة .ini فقط)
   لإضافة فلتر جديد: أضف سطراً جديداً داخل المصفوفة بالدالة P(...)
   ملف الفلتر يُرفع على السيرفر بجانب بقية الملفات ثم يُكتب اسمه هنا.
============================================================ */
const PRESETS_BASE_URL = "http://169.58.57.199/";

// P(الاسم المعروض، اسم الملف .ini، الوصف، رابط الصورة (اختياري)، الحجم (اختياري))
const P = (name, file, description = "", img = "", size = "") => ({
    id: file.replace(/\.ini$/i, "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, ""),
    name, file, description, img, size,
    url: PRESETS_BASE_URL + encodeURIComponent(file)
});

const PRESETS = [
    // أمثلة (احذف علامة التعليق بعد رفع الملف على السيرفر):
    // P("CA - Best 1", "CA - Best 1 - preset.ini", "ألوان حيّة وتباين عالٍ", "../assets/presets/best1.png", "70 KB"),
    // P("CA - Snow",   "CA - Snow - preset.ini",   "أجواء شتوية باردة",     "../assets/presets/snow.png",  "28 KB"),
];

app.get("/api/presets", (req, res) => {
    // نرسل فقط الملفات بصيغة .ini
    res.json({ success: true, presets: PRESETS.filter(p => /\.ini$/i.test(p.file)) });
});

/* ============================================================
   ██████  CA STORE — WEBSITE API  (المنتجات / التقييمات / المشتريات / الأدمن)
   ------------------------------------------------------------
   • الأدمن يُحدَّد بحساب ديسكورد (ADMIN_DISCORD_ID + اختيارياً STORE_ADMIN_IDS في Railway)
     ويدخل بنفس تسجيل دخول ديسكورد للموقع — لا توجد كلمة سر.
   • التقييم مسموح فقط لمن اشترى المنتج (رتبة الباك في ديسكورد أو سجل شراء).
============================================================ */
const STORE_ADMIN_IDS = [ADMIN_DISCORD_ID, ...(process.env.STORE_ADMIN_IDS || "").split(",").map(s => s.trim()).filter(Boolean)];
const isStoreAdmin = (id) => !!id && STORE_ADMIN_IDS.includes(String(id));

const storeReadLimiter = rateLimit({ windowMs: 60 * 1000, max: 120, standardHeaders: true, legacyHeaders: false, message: { success: false, message: "طلبات كثيرة" } });
const storeReviewLimiter = rateLimit({ windowMs: 60 * 1000, max: 8, standardHeaders: true, legacyHeaders: false, message: { success: false, message: "محاولات كثيرة، انتظر قليلاً" } });
const storeAdminLimiter = rateLimit({ windowMs: 60 * 1000, max: 120, standardHeaders: true, legacyHeaders: false, message: { success: false, message: "طلبات كثيرة" } });

/* ── tables ── */
const STORE_SEED = [
    { id: 1, title: "جرافيكس فايف ام | 𝐂𝐚-𝟏-𝐏𝐚𝐜𝐤", description: "CA-1 PACK نسخة\n\nجرافيكس مخصص للفايتات مع لمسة واقعية جميلة.\n\nاضاءة نهارية في جميع اوقات اللعبة لرؤية واضحة\n\nسماء الشفق (Aurora) بمظهر خيالي وجذاب\n\nقائمة تحكم كاملة لتعديل لون الشجر ولون البحر، مع تحكم شامل بالسماء (ألوان + غيوم)\n\nفلتر SSR احترافي مناسب للتصوير وللعب\n\nكيل افيكت Killeffect\n\nتأثيرات دماء بعد الدمج\n\nتخفيف سطوع الشمس لراحة أفضل للعين وتوازن بصري أجمل\n\nإمكانية تغيير الطقس إلى ثلج للتصوير\n\nفلتر البلور للتصوير\n\nبعد شرائك المنتج بادر بفتح تذكرة بسيرفر الديسكورد.", price: 40, old_price: 55, image: "CA-1 (2).png", category: "fivem", status: "available", payment_url: "https://www.paypal.com/ncp/payment/28Q47CF3QFH5L", plan: "CA-1" },
    { id: 2, title: "جرافيكس فايف ام | 𝐂𝐚-𝟐-𝐏𝐚𝐜𝐤", description: "CA-2 PACK الإصدار الجديد\n\nتجربة جرافيكس مطوّرة بالكامل، مصممة للفايتات والتصوير الاحترافي، مع تحسينات بصرية عميقة تعطيك واقعية أعلى وثبات أفضل داخل اللعبة.\n\n🔹 10 فلاتر جاهزة بتدرجات مختلفة\n🔹 إضاءة نهارية محسّنة وواضحة\n🔹 سماء ديناميكية مع تأثيرات Aurora & Galaxy\n🔹 تحكم كامل بالألوان (الشجر – البحر – السماء – الغيوم – الشوارع)\n🔹 فلتر SSR مطوّر\n🔹 Killeffect محسّن\n🔹 تأثيرات مطر على الشاشة والسيارة\n🔹 تأثيرات دماء واقعية\n🔹 فلتر خاص للفايتات الليلية\n🔹 فلتر Blur احترافي\n🔹 إمكانية تغيير الطقس إلى ثلج\n\nبعد الشراء افتح تذكرة في سيرفر الديسكورد.", price: 47, old_price: 59.99, image: "combined_image_small.png", category: "fivem", status: "available", payment_url: "https://www.paypal.com/ncp/payment/BQV36TDMKEZZS", plan: "CA-2" },
    { id: 3, title: "جرافيكس فايف ام | 𝐂𝐚-𝟑-𝐏𝐚𝐜𝐤", description: "استمتع بتجربة بصرية استثنائية مع هذا الجرافيكس المتطور المبني على الواقعية.", price: 50, old_price: 69.99, image: "ca3-2.png", category: "fivem", status: "available", payment_url: "https://www.paypal.com/ncp/payment/4NCQANM2FJA2Q", plan: "CA-3" },
    { id: 4, title: "جرافيكس فايف ام | 𝐂𝐚-𝟒-𝐏𝐚𝐜𝐤", description: "CA-4 PACK الإصدار الأقوى\n\nجيل جديد من الجرافيكس المطوّر بالكامل، مبني على واقعية أعلى، إضاءة سينمائية، وألوان محسّنة تعطيك تجربة لعب مختلفة تمامًا. تم تصميمه ليجمع بين الجودة الفائقة والأداء السلس بدون أي هبوط في الـ FPS.\n\n🔹 إضاءة سينمائية محسّنة بجيل جديد من الـ HDR\n🔹 تحويل شواطئ لوس بالكامل من تراب الى عشب\n🔹 ظلال أكثر دقة ووضوح في كل المشاهد\n🔹 تأثيرات انعكاس SSR مطوّرة بالكامل\n🔹 تحسينات ضخمة على الشجر – المباني – الشوارع – السماء\n🔹 سماء ديناميكية مع تأثيرات Galaxy & Aurora بجودة أعلى من CA-2\n🔹 تأثيرات مطر وبلل على الشاشة والسيارة بجودة 4K\n🔹 تأثيرات دماء واقعية محسّنة للفايتات\n🔹 تحويل ساندي الى صحراء بشكل واقعي ومريح بصريااا\n🔹 دعم كامل للتصوير السينمائي واللقطات الاحترافية\n🔹 أداء ثابت بدون استهلاك عالي للموارد\n\nبعد الشراء افتح تذكرة في سيرفر الديسكورد.", price: 60, old_price: 70, image: "ca4.png", category: "fivem", status: "available", payment_url: "https://www.paypal.com/ncp/payment/VDA6SB9T3UYLY", plan: "CA-4" },
    { id: 5, title: "جرافيكس فايف ام | 𝐂𝐚-𝟓-𝐏𝐚𝐜𝐤", description: "CA-5 PACK – الجيل الأحدث والأقوى من سلسلة CA\n\n🔹 بالرغم من الواقعية الرؤية واضحة ليلا مع امكانية التحكم بالاضاءة\n🔹 ألوان مشبعة وتوازن بصري احترافي في جميع الأوقات\n🔹 تحويل ساندي بالكامل إلى بيئة خضراء مغطاة بالعشب بتفاصيل مذهلة\n🔹 سماء المجرة والشفق القطبي مع امكانية تغيير موقعهم بالمساء بالاضافة الى الالوان\n🔹 انعكاسات  واقعية على السيارات والمباني والشوارع\n🔹 تحسينات ضخمة على الأشجار – المباني – الطرق – الجبال – المياه\n🔹 ظلال أكثر دقة وعمقًا في جميع المشاهد\n🔹 تأثيرات مطر وبلل على الشاشة والسيارات بجودة 4K\n🔹 تحسينات بصرية متقدمة للتصوير وصناعة المحتوى\n🔹 تأثيرات دماء واقعية محسّنة للمعارك واللقطات السينمائية\n🔹 بيئة أكثر حيوية وتفاصيل طبيعية\n\nبعد الشراء افتح تذكرة في سيرفر الديسكورد.", price: 95, old_price: 105, image: "CA5.png", category: "fivem", status: "available", payment_url: "https://www.paypal.com/ncp/payment/YMWC9FMJFZYEU", plan: "CA-5" },
    { id: 6, title: "ChatGPT Plus – اشتراك شهر واحد", description: "اشتراك رسمي لمدة شهر – تفعيل فوري", price: 21.99, image: "cg.png", category: "subscriptions", status: "out", payment_url: "https://www.paypal.com/ncp/payment/UR9YGZDLBQY6J" },
    { id: 7, title: "Nitro Gaming – 1 month", description: "هذا المنتج غير متوفر حاليًا", price: 25, image: "Nitro.png", category: "discord", status: "out", payment_url: null },
    { id: 8, title: "بوت تذاكر خاص لـ سيرفرك", description: "بوت تذاكر احترافي ومخصص بالكامل لسيرفرك.", price: 18.75, image: "ticket.png", category: "discord", status: "out", payment_url: "https://www.paypal.com/ncp/payment/HCAWEE5YCNB8J" },
    { id: 9, title: "بوت كامل خاص لـ سيرفرك", description: "بوت متكامل مصمم خصيصًا لسيرفرك.", price: 56.29, image: "bot.png", category: "discord", status: "out", payment_url: "https://www.paypal.com/ncp/payment/ZS9V7N65HG8U6" },
    { id: 10, title: "14 بوست لمدة شهر", description: "🚀 ديسكورد – 14 بوست لمدة شهر كامل 🚀", price: 31.9, image: "boost.png", category: "discord", status: "available", payment_url: "https://www.paypal.com/ncp/payment/4GT9FKFDKURAU" },
    { id: 11, title: "دعم المتجر", description: "ادعم CA Store وساعدنا في تقديم منتجات أفضل وتطوير المتجر.\n\nيمكنك اختيار المبلغ الذي تريد دعمه من خلال رابط StreamLabs.", price: 0, image: "Ca.png", category: "support", status: "available", payment_url: "https://streamlabs.com/r-i-c-k1/tip", is_support: true }
];

(async () => {
    try {
        await db.query(`CREATE TABLE IF NOT EXISTS store_products (
            id SERIAL PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            price NUMERIC(10,2) NOT NULL DEFAULT 0,
            old_price NUMERIC(10,2),
            image TEXT NOT NULL DEFAULT '',
            category TEXT NOT NULL DEFAULT 'fivem',
            status TEXT NOT NULL DEFAULT 'available',
            plan TEXT,
            payment_url TEXT,
            is_support BOOLEAN NOT NULL DEFAULT FALSE,
            featured BOOLEAN NOT NULL DEFAULT FALSE,
            sort_order INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW()
        )`);
        await db.query(`CREATE TABLE IF NOT EXISTS store_reviews (
            id SERIAL PRIMARY KEY,
            product_id INTEGER NOT NULL,
            discord_id TEXT NOT NULL,
            username TEXT NOT NULL,
            avatar TEXT,
            rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
            comment TEXT NOT NULL DEFAULT '',
            created_at TIMESTAMP DEFAULT NOW(),
            UNIQUE (product_id, discord_id)
        )`);
        await db.query(`CREATE TABLE IF NOT EXISTS store_purchases (
            id SERIAL PRIMARY KEY,
            discord_id TEXT NOT NULL,
            product_id INTEGER,
            plan TEXT,
            amount TEXT,
            method TEXT,
            source TEXT NOT NULL DEFAULT 'webhook',
            created_at TIMESTAMP DEFAULT NOW()
        )`);
        await db.query(`CREATE INDEX IF NOT EXISTS idx_store_reviews_product ON store_reviews(product_id)`);
        await db.query(`CREATE INDEX IF NOT EXISTS idx_store_purchases_user ON store_purchases(discord_id)`);

        const { rows } = await db.query("SELECT COUNT(*)::int AS n FROM store_products");
        if (rows[0].n === 0) {
            let order = 0;
            for (const p of STORE_SEED) {
                await db.query(
                    `INSERT INTO store_products (id,title,description,price,old_price,image,category,status,plan,payment_url,is_support,featured,sort_order)
                     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
                    [p.id, p.title, p.description, p.price, p.old_price || null, p.image, p.category, p.status, p.plan || null, p.payment_url || null, !!p.is_support, p.id === 5, order++]
                );
            }
            await db.query("SELECT setval(pg_get_serial_sequence('store_products','id'), (SELECT MAX(id) FROM store_products))");
            console.log("✅ Store products seeded");
        }
    } catch (err) { console.error("Store init error:", err); }
})();

/* ── helpers ── */
const PRODUCT_STATUSES = ["available", "out", "hidden"];

function productRow(r) {
    return {
        id: r.id, title: r.title, description: r.description,
        price: Number(r.price), oldPrice: r.old_price == null ? null : Number(r.old_price),
        image: r.image, category: r.category, status: r.status, plan: r.plan,
        paymentUrl: r.status === "available" ? r.payment_url : null,
        isSupport: r.is_support, featured: r.featured, sortOrder: r.sort_order,
        rating: { avg: r.avg == null ? 0 : Number(Number(r.avg).toFixed(1)), count: r.cnt == null ? 0 : Number(r.cnt) },
        createdAt: r.created_at
    };
}
const PRODUCT_SELECT = `
    SELECT p.*, r.avg, r.cnt FROM store_products p
    LEFT JOIN (SELECT product_id, AVG(rating) AS avg, COUNT(*) AS cnt FROM store_reviews GROUP BY product_id) r ON r.product_id = p.id`;

function reviewRow(r) {
    return {
        id: r.id, productId: r.product_id, productTitle: r.product_title || undefined,
        username: r.username, avatar: r.avatar, rating: r.rating, comment: r.comment,
        verified: true, createdAt: r.created_at, discordId: r.discord_id
    };
}

function authUser(required) {
    return async (req, res, next) => {
        const h = req.headers.authorization || "";
        const token = h.startsWith("Bearer ") ? h.slice(7) : "";
        if (!token) { if (required) return res.status(401).json({ success: false, message: "سجّل الدخول أولاً" }); req.user = null; return next(); }
        try {
            const d = jwt.verify(token, JWT_SECRET);
            if (!d.discordId) throw new Error("bad token");
            if (d.sessionId) {
                const s = await db.query("SELECT 1 FROM web_sessions WHERE session_id=$1 AND expires_at > NOW()", [d.sessionId]);
                if (!s.rows.length) throw new Error("session expired");
            }
            req.user = { discordId: String(d.discordId) };
            next();
        } catch {
            if (required) return res.status(401).json({ success: false, message: "انتهت الجلسة، سجّل الدخول من جديد" });
            req.user = null; next();
        }
    };
}
const requireAdmin = [storeAdminLimiter, authUser(true), (req, res, next) => {
    if (!isStoreAdmin(req.user.discordId)) return res.status(403).json({ success: false, message: "غير مصرح" });
    next();
}];

async function fetchDiscordProfile(discordId) {
    try {
        const r = await fetch(`https://discord.com/api/users/${discordId}`, { headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` } });
        const u = await r.json();
        return {
            username: u.global_name || u.username || "عميل",
            avatar: u.avatar ? `https://cdn.discordapp.com/avatars/${discordId}/${u.avatar}.png?size=128` : null
        };
    } catch { return { username: "عميل", avatar: null }; }
}

async function userOwnsProduct(discordId, product) {
    const p = await db.query("SELECT 1 FROM store_purchases WHERE discord_id=$1 AND product_id=$2 LIMIT 1", [discordId, product.id]);
    if (p.rows.length) return true;
    if (product.plan) {
        try { const plans = await getPlansFromDiscord(discordId); if (plans && plans.includes(product.plan)) return true; } catch {}
    }
    return false;
}

async function recordPurchase(discordId, plan, amount, method, source = "webhook") {
    try {
        const prod = plan ? await db.query("SELECT id FROM store_products WHERE plan=$1 ORDER BY id LIMIT 1", [plan]) : { rows: [] };
        await db.query(
            "INSERT INTO store_purchases (discord_id, product_id, plan, amount, method, source) VALUES ($1,$2,$3,$4,$5,$6)",
            [String(discordId), prod.rows[0] ? prod.rows[0].id : null, plan || null, amount == null ? null : String(amount), method || null, source]
        );
    } catch (err) { console.error("recordPurchase error:", err); }
}

function cleanProduct(b, partial = false) {
    const out = {};
    const str = (v) => (typeof v === "string" ? v.trim() : "");
    const num = (v) => (v === "" || v === null || v === undefined ? null : Number(v));

    if (!partial || b.title !== undefined) { out.title = str(b.title); if (out.title.length < 2 || out.title.length > 160) return { error: "اسم المنتج بين 2 و160 حرفاً" }; }
    if (!partial || b.description !== undefined) { out.description = typeof b.description === "string" ? b.description.slice(0, 8000) : ""; }
    if (!partial || b.price !== undefined) { out.price = num(b.price); if (out.price === null || !isFinite(out.price) || out.price < 0 || out.price > 100000) return { error: "السعر غير صالح" }; }
    if (!partial || b.oldPrice !== undefined) { out.old_price = num(b.oldPrice); if (out.old_price !== null && (!isFinite(out.old_price) || out.old_price < 0 || out.old_price > 100000)) return { error: "السعر القديم غير صالح" }; }
    if (!partial || b.image !== undefined) { out.image = str(b.image).slice(0, 600); }
    if (!partial || b.category !== undefined) { out.category = str(b.category).toLowerCase().replace(/[^a-z0-9_\-؀-ۿ]/g, "").slice(0, 40) || "other"; }
    if (!partial || b.status !== undefined) { out.status = str(b.status) || "available"; if (!PRODUCT_STATUSES.includes(out.status)) return { error: "حالة المنتج غير صالحة" }; }
    if (!partial || b.plan !== undefined) { const pl = str(b.plan); if (pl && !PLAN_ROLE_MAP[pl]) return { error: "اسم النسخة (Plan) غير معروف" }; out.plan = pl || null; }
    if (!partial || b.isSupport !== undefined) out.is_support = !!b.isSupport;
    if (!partial || b.featured !== undefined) out.featured = !!b.featured;
    if (!partial || b.sortOrder !== undefined) { const n = parseInt(b.sortOrder, 10); out.sort_order = isFinite(n) ? n : 0; }
    if (!partial || b.paymentUrl !== undefined) {
        const u = str(b.paymentUrl);
        if (u) {
            let parsed; try { parsed = new URL(u); } catch { return { error: "رابط الدفع غير صالح" }; }
            if (parsed.protocol !== "https:") return { error: "رابط الدفع يجب أن يبدأ بـ https://" };
            out.payment_url = parsed.toString().length > 600 ? null : parsed.toString();
        } else out.payment_url = null;
    }
    return { value: out };
}

/* ── PUBLIC ── */
app.get("/api/store/products", storeReadLimiter, async (req, res) => {
    try {
        const r = await db.query(`${PRODUCT_SELECT} WHERE p.status <> 'hidden' ORDER BY p.sort_order ASC, p.id ASC`);
        res.json({ success: true, products: r.rows.map(productRow) });
    } catch (err) { console.error(err); res.status(500).json({ success: false, message: "خطأ في جلب المنتجات" }); }
});

app.get("/api/store/me", storeReadLimiter, authUser(true), async (req, res) => {
    const prof = await fetchDiscordProfile(req.user.discordId);
    let plans = [];
    try { plans = (await getPlansFromDiscord(req.user.discordId)) || []; } catch {}
    res.json({ success: true, discordId: req.user.discordId, username: prof.username, avatar: prof.avatar, plans, isAdmin: isStoreAdmin(req.user.discordId) });
});

app.get("/api/store/reviews", storeReadLimiter, async (req, res) => {
    try {
        const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 12, 1), 60);
        const r = await db.query(
            `SELECT v.*, p.title AS product_title FROM store_reviews v JOIN store_products p ON p.id = v.product_id
             WHERE p.status <> 'hidden' ORDER BY v.created_at DESC LIMIT $1`, [limit]);
        const stats = await db.query(`SELECT COALESCE(AVG(rating),0) AS avg, COUNT(*)::int AS cnt FROM store_reviews`);
        res.json({ success: true, reviews: r.rows.map(x => { const o = reviewRow(x); delete o.discordId; return o; }), summary: { avg: Number(Number(stats.rows[0].avg).toFixed(1)), count: stats.rows[0].cnt } });
    } catch (err) { console.error(err); res.status(500).json({ success: false, message: "خطأ في جلب التقييمات" }); }
});

app.get("/api/store/products/:id/reviews", storeReadLimiter, authUser(false), async (req, res) => {
    try {
        const id = parseInt(req.params.id, 10);
        const pr = await db.query("SELECT * FROM store_products WHERE id=$1 AND status <> 'hidden'", [id]);
        if (!pr.rows.length) return res.status(404).json({ success: false, message: "المنتج غير موجود" });
        const rv = await db.query("SELECT * FROM store_reviews WHERE product_id=$1 ORDER BY created_at DESC", [id]);
        const dist = [0, 0, 0, 0, 0]; let sum = 0;
        rv.rows.forEach(x => { dist[x.rating - 1]++; sum += x.rating; });
        const me = { loggedIn: !!req.user, isAdmin: false, canReview: false, myReview: null, reason: req.user ? "" : "login" };
        if (req.user) {
            me.isAdmin = isStoreAdmin(req.user.discordId);
            const mine = rv.rows.find(x => x.discord_id === req.user.discordId);
            me.myReview = mine ? { id: mine.id, rating: mine.rating, comment: mine.comment } : null;
            me.canReview = await userOwnsProduct(req.user.discordId, pr.rows[0]);
            if (!me.canReview) me.reason = "not_purchased";
        }
        res.json({
            success: true,
            summary: { avg: rv.rows.length ? Number((sum / rv.rows.length).toFixed(1)) : 0, count: rv.rows.length, distribution: dist },
            reviews: rv.rows.map(x => { const o = reviewRow(x); delete o.discordId; o.mine = !!(req.user && x.discord_id === req.user.discordId); return o; }),
            me
        });
    } catch (err) { console.error(err); res.status(500).json({ success: false, message: "خطأ في جلب التقييمات" }); }
});

/* ── REVIEWS (مشترون فقط) ── */
app.post("/api/store/reviews", storeReviewLimiter, authUser(true), async (req, res) => {
    try {
        const productId = parseInt(req.body.productId, 10);
        const rating = parseInt(req.body.rating, 10);
        const comment = typeof req.body.comment === "string" ? req.body.comment.trim().slice(0, 600) : "";
        if (!productId || !(rating >= 1 && rating <= 5)) return res.json({ success: false, message: "بيانات غير صالحة" });

        const pr = await db.query("SELECT * FROM store_products WHERE id=$1 AND status <> 'hidden'", [productId]);
        if (!pr.rows.length) return res.json({ success: false, message: "المنتج غير موجود" });
        if (!(await userOwnsProduct(req.user.discordId, pr.rows[0]))) {
            return res.status(403).json({ success: false, message: "التقييم متاح فقط لمن اشترى هذا المنتج" });
        }
        const prof = await fetchDiscordProfile(req.user.discordId);
        await db.query(
            `INSERT INTO store_reviews (product_id, discord_id, username, avatar, rating, comment)
             VALUES ($1,$2,$3,$4,$5,$6)
             ON CONFLICT (product_id, discord_id) DO UPDATE SET rating=EXCLUDED.rating, comment=EXCLUDED.comment, username=EXCLUDED.username, avatar=EXCLUDED.avatar, created_at=NOW()`,
            [productId, req.user.discordId, prof.username, prof.avatar, rating, comment]);
        res.json({ success: true });
    } catch (err) { console.error(err); res.status(500).json({ success: false, message: "تعذّر إرسال التقييم" }); }
});

app.delete("/api/store/reviews/:id", storeReviewLimiter, authUser(true), async (req, res) => {
    try {
        const id = parseInt(req.params.id, 10);
        const r = await db.query("SELECT * FROM store_reviews WHERE id=$1", [id]);
        if (!r.rows.length) return res.json({ success: false, message: "التقييم غير موجود" });
        if (r.rows[0].discord_id !== req.user.discordId && !isStoreAdmin(req.user.discordId)) return res.status(403).json({ success: false, message: "غير مصرح" });
        await db.query("DELETE FROM store_reviews WHERE id=$1", [id]);
        res.json({ success: true });
    } catch (err) { console.error(err); res.status(500).json({ success: false, message: "تعذّر الحذف" }); }
});

/* ── ADMIN ── */
app.get("/api/admin/store/products", requireAdmin, async (req, res) => {
    try {
        const r = await db.query(`${PRODUCT_SELECT} ORDER BY p.sort_order ASC, p.id ASC`);
        // الأدمن يرى رابط الدفع دائماً حتى للمنتجات غير المتوفرة
        res.json({ success: true, products: r.rows.map(x => ({ ...productRow(x), paymentUrl: x.payment_url })) });
    } catch (err) { console.error(err); res.status(500).json({ success: false, message: "خطأ" }); }
});

app.post("/api/admin/store/products", requireAdmin, async (req, res) => {
    try {
        const c = cleanProduct(req.body);
        if (c.error) return res.json({ success: false, message: c.error });
        const v = c.value;
        if (v.status === "available" && !v.payment_url) return res.json({ success: false, message: "رابط الدفع مطلوب للمنتج المتوفر" });
        const next = await db.query("SELECT COALESCE(MAX(sort_order),0)+1 AS n FROM store_products");
        if (req.body.sortOrder === undefined || req.body.sortOrder === "") v.sort_order = next.rows[0].n;
        const r = await db.query(
            `INSERT INTO store_products (title,description,price,old_price,image,category,status,plan,payment_url,is_support,featured,sort_order)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id`,
            [v.title, v.description, v.price, v.old_price, v.image, v.category, v.status, v.plan, v.payment_url, v.is_support, v.featured, v.sort_order]);
        res.json({ success: true, id: r.rows[0].id });
    } catch (err) { console.error(err); res.status(500).json({ success: false, message: "تعذّر إضافة المنتج" }); }
});

app.put("/api/admin/store/products/:id", requireAdmin, async (req, res) => {
    try {
        const id = parseInt(req.params.id, 10);
        const cur = await db.query("SELECT * FROM store_products WHERE id=$1", [id]);
        if (!cur.rows.length) return res.json({ success: false, message: "المنتج غير موجود" });
        const c = cleanProduct(req.body, true);
        if (c.error) return res.json({ success: false, message: c.error });
        const v = c.value;
        const finalStatus = v.status !== undefined ? v.status : cur.rows[0].status;
        const finalUrl = v.payment_url !== undefined ? v.payment_url : cur.rows[0].payment_url;
        if (finalStatus === "available" && !finalUrl) return res.json({ success: false, message: "رابط الدفع مطلوب للمنتج المتوفر" });
        const keys = Object.keys(v);
        if (!keys.length) return res.json({ success: true });
        const sets = keys.map((k, i) => `${k}=$${i + 1}`).join(", ");
        await db.query(`UPDATE store_products SET ${sets}, updated_at=NOW() WHERE id=$${keys.length + 1}`, [...keys.map(k => v[k]), id]);
        res.json({ success: true });
    } catch (err) { console.error(err); res.status(500).json({ success: false, message: "تعذّر تعديل المنتج" }); }
});

app.delete("/api/admin/store/products/:id", requireAdmin, async (req, res) => {
    try {
        const id = parseInt(req.params.id, 10);
        await db.query("DELETE FROM store_reviews WHERE product_id=$1", [id]);
        await db.query("UPDATE store_purchases SET product_id=NULL WHERE product_id=$1", [id]);
        const r = await db.query("DELETE FROM store_products WHERE id=$1", [id]);
        res.json({ success: r.rowCount > 0, message: r.rowCount ? undefined : "المنتج غير موجود" });
    } catch (err) { console.error(err); res.status(500).json({ success: false, message: "تعذّر حذف المنتج" }); }
});

app.get("/api/admin/store/reviews", requireAdmin, async (req, res) => {
    try {
        const r = await db.query(`SELECT v.*, p.title AS product_title FROM store_reviews v LEFT JOIN store_products p ON p.id = v.product_id ORDER BY v.created_at DESC LIMIT 500`);
        res.json({ success: true, reviews: r.rows.map(reviewRow) });
    } catch (err) { console.error(err); res.status(500).json({ success: false, message: "خطأ" }); }
});

app.get("/api/admin/store/purchases", requireAdmin, async (req, res) => {
    try {
        const r = await db.query(`SELECT s.*, p.title AS product_title FROM store_purchases s LEFT JOIN store_products p ON p.id = s.product_id ORDER BY s.created_at DESC LIMIT 300`);
        res.json({ success: true, purchases: r.rows.map(x => ({ id: x.id, discordId: x.discord_id, productId: x.product_id, productTitle: x.product_title, plan: x.plan, amount: x.amount, method: x.method, source: x.source, createdAt: x.created_at })) });
    } catch (err) { console.error(err); res.status(500).json({ success: false, message: "خطأ" }); }
});

/* إضافة شراء يدوياً (مثلاً للمنتجات التي لا تمنح رتبة تلقائياً) → يسمح للعميل بالتقييم */
app.post("/api/admin/store/purchases", requireAdmin, async (req, res) => {
    try {
        const discordId = String(req.body.discordId || "").trim();
        const productId = parseInt(req.body.productId, 10);
        if (!/^\d{15,22}$/.test(discordId) || !productId) return res.json({ success: false, message: "أدخل آيدي ديسكورد صحيح واختر المنتج" });
        const p = await db.query("SELECT id, plan, price FROM store_products WHERE id=$1", [productId]);
        if (!p.rows.length) return res.json({ success: false, message: "المنتج غير موجود" });
        await db.query("INSERT INTO store_purchases (discord_id, product_id, plan, amount, method, source) VALUES ($1,$2,$3,$4,$5,'admin')",
            [discordId, productId, p.rows[0].plan, String(p.rows[0].price), "Manual"]);
        res.json({ success: true });
    } catch (err) { console.error(err); res.status(500).json({ success: false, message: "تعذّرت الإضافة" }); }
});

app.delete("/api/admin/store/purchases/:id", requireAdmin, async (req, res) => {
    try { await db.query("DELETE FROM store_purchases WHERE id=$1", [parseInt(req.params.id, 10)]); res.json({ success: true }); }
    catch (err) { console.error(err); res.status(500).json({ success: false, message: "تعذّر الحذف" }); }
});

app.get("/api/admin/store/stats", requireAdmin, async (req, res) => {
    try {
        const [p, r, s, rev] = await Promise.all([
            db.query("SELECT COUNT(*)::int AS total, COUNT(*) FILTER (WHERE status='available')::int AS available FROM store_products"),
            db.query("SELECT COUNT(*)::int AS cnt, COALESCE(AVG(rating),0) AS avg FROM store_reviews"),
            db.query("SELECT COUNT(*)::int AS cnt FROM store_purchases"),
            db.query("SELECT COALESCE(SUM(NULLIF(regexp_replace(amount,'[^0-9.]','','g'),'')::numeric),0) AS total FROM store_purchases")
        ]);
        res.json({ success: true, stats: { products: p.rows[0].total, available: p.rows[0].available, reviews: r.rows[0].cnt, avgRating: Number(Number(r.rows[0].avg).toFixed(1)), purchases: s.rows[0].cnt, revenue: Number(rev.rows[0].total) } });
    } catch (err) { console.error(err); res.status(500).json({ success: false, message: "خطأ" }); }
});

/* ============================================================
   CHECKOUT — دفع PayPal مرتبط بحساب ديسكورد (Orders API)
   متغيرات Railway: PAYPAL_CLIENT_ID , PAYPAL_CLIENT_SECRET
   اختياري: PAYPAL_ENV=sandbox للتجربة
============================================================ */
const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID || "";
const PAYPAL_CLIENT_SECRET = process.env.PAYPAL_CLIENT_SECRET || "";
const PAYPAL_API = process.env.PAYPAL_ENV === "sandbox" ? "https://api-m.sandbox.paypal.com" : "https://api-m.paypal.com";
const checkoutLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 25, standardHeaders: true, legacyHeaders: false, message: { success: false, message: "محاولات كثيرة، انتظر قليلاً" } });

let _ppToken = { value: null, exp: 0 };
async function paypalToken() {
    if (_ppToken.value && Date.now() < _ppToken.exp) return _ppToken.value;
    const r = await fetch(`${PAYPAL_API}/v1/oauth2/token`, {
        method: "POST",
        headers: { Authorization: "Basic " + Buffer.from(`${PAYPAL_CLIENT_ID}:${PAYPAL_CLIENT_SECRET}`).toString("base64"), "Content-Type": "application/x-www-form-urlencoded" },
        body: "grant_type=client_credentials"
    });
    const d = await r.json();
    if (!d.access_token) { console.error("❌ PayPal token error:", d); throw new Error("paypal_auth"); }
    _ppToken = { value: d.access_token, exp: Date.now() + Math.max((d.expires_in || 300) - 60, 30) * 1000 };
    return _ppToken.value;
}
async function paypalCall(method, path, body, reqId) {
    const t = await paypalToken();
    const headers = { Authorization: `Bearer ${t}`, "Content-Type": "application/json" };
    if (reqId) headers["PayPal-Request-Id"] = reqId;
    const r = await fetch(`${PAYPAL_API}${path}`, { method, headers, body: body ? JSON.stringify(body) : undefined });
    let d = {}; try { d = await r.json(); } catch {}
    return { status: r.status, data: d };
}

let _chkSchema = null;
function ensureCheckoutSchema() {
    if (!_chkSchema) _chkSchema = (async () => {
        await db.query(`ALTER TABLE store_purchases ADD COLUMN IF NOT EXISTS paypal_order_id TEXT`);
        await db.query(`CREATE UNIQUE INDEX IF NOT EXISTS uq_store_purchases_order ON store_purchases(paypal_order_id) WHERE paypal_order_id IS NOT NULL`);
    })().catch(e => { _chkSchema = null; throw e; });
    return _chkSchema;
}

// هل الدفع التلقائي مفعّل؟ (الموقع يستخدمه ليقرر الطريقة)
app.get("/api/store/checkout/status", (req, res) => res.json({ success: true, enabled: !!(PAYPAL_CLIENT_ID && PAYPAL_CLIENT_SECRET) }));

// إنشاء طلب دفع وإرجاع رابط PayPal
app.post("/api/store/checkout", checkoutLimiter, authUser(true), async (req, res) => {
    if (!PAYPAL_CLIENT_ID || !PAYPAL_CLIENT_SECRET) return res.status(503).json({ success: false, code: "checkout_disabled", message: "الدفع التلقائي غير مفعّل" });
    try {
        const productId = parseInt(req.body.productId, 10);
        const pr = productId ? await db.query("SELECT * FROM store_products WHERE id=$1", [productId]) : { rows: [] };
        const p = pr.rows[0];
        if (!p || p.status !== "available") return res.json({ success: false, message: "المنتج غير متوفر حالياً" });
        if (p.is_support) return res.json({ success: false, message: "منتج الدعم يتم عبر رابطه المباشر" });
        const price = Number(p.price);
        if (!(price > 0)) return res.json({ success: false, message: "سعر المنتج غير صالح" });

        const site = WEBSITE_URL.replace(/\/+$/, "");
        const order = await paypalCall("POST", "/v2/checkout/orders", {
            intent: "CAPTURE",
            purchase_units: [{
                reference_id: `p${p.id}`,
                custom_id: `d=${req.user.discordId}&p=${p.id}`,
                description: String(p.title).slice(0, 120),
                amount: { currency_code: "USD", value: price.toFixed(2) }
            }],
            payment_source: { paypal: { experience_context: {
                brand_name: "CA Store", user_action: "PAY_NOW", shipping_preference: "NO_SHIPPING", landing_page: "GUEST_CHECKOUT",
                return_url: `${site}/checkout-return.html`, cancel_url: `${site}/product.html?id=${p.id}`
            } } }
        }, crypto.randomBytes(16).toString("hex"));

        const link = (order.data.links || []).find(l => l.rel === "payer-action") || (order.data.links || []).find(l => l.rel === "approve");
        if (!link) { console.error("❌ PayPal create order failed:", JSON.stringify(order.data)); return res.json({ success: false, message: "تعذّر بدء الدفع، حاول لاحقاً" }); }
        res.json({ success: true, url: link.href, orderId: order.data.id });
    } catch (err) { console.error("checkout error:", err); res.status(500).json({ success: false, message: "تعذّر بدء الدفع" }); }
});

// بعد رجوع العميل من PayPal: التقاط الدفعة ثم تسجيل الشراء وإعطاء الرتبة
app.post("/api/store/checkout/capture", checkoutLimiter, authUser(true), async (req, res) => {
    if (!PAYPAL_CLIENT_ID || !PAYPAL_CLIENT_SECRET) return res.status(503).json({ success: false, code: "checkout_disabled", message: "الدفع التلقائي غير مفعّل" });
    try {
        await ensureCheckoutSchema();
        const orderId = String(req.body.orderId || "").trim();
        if (!/^[A-Za-z0-9\-]{8,40}$/.test(orderId)) return res.json({ success: false, message: "رقم الطلب غير صالح" });

        const got = await paypalCall("GET", `/v2/checkout/orders/${orderId}`);
        if (got.status !== 200) return res.json({ success: false, message: "لم يتم العثور على الطلب" });
        let order = got.data;
        const unit = (order.purchase_units || [])[0] || {};
        const cm = new URLSearchParams(unit.custom_id || "");
        if (cm.get("d") !== req.user.discordId) return res.status(403).json({ success: false, message: "هذا الطلب لا يخص حسابك" });
        const productId = parseInt(cm.get("p"), 10);

        if (order.status === "APPROVED") {
            const cap = await paypalCall("POST", `/v2/checkout/orders/${orderId}/capture`, undefined, "cap-" + orderId);
            if (cap.status >= 400 && !(cap.data && cap.data.status === "COMPLETED")) { console.error("❌ capture failed:", JSON.stringify(cap.data)); return res.json({ success: false, message: "فشل إتمام الدفع" }); }
            order = cap.data.status ? cap.data : order;
            const again = await paypalCall("GET", `/v2/checkout/orders/${orderId}`); if (again.status === 200) order = again.data;
        }
        if (order.status !== "COMPLETED") return res.json({ success: false, pending: order.status !== "VOIDED", message: order.status === "CREATED" ? "لم يتم تأكيد الدفع في PayPal بعد" : "لم يكتمل الدفع" });

        const capture = (((order.purchase_units || [])[0] || {}).payments || {}).captures;
        const amount = capture && capture[0] ? capture[0].amount.value : (unit.amount || {}).value;
        const pr = await db.query("SELECT * FROM store_products WHERE id=$1", [productId]);
        const p = pr.rows[0];
        const plan = p && p.plan ? p.plan : null;

        const ins = await db.query(
            `INSERT INTO store_purchases (discord_id, product_id, plan, amount, method, source, paypal_order_id)
             VALUES ($1,$2,$3,$4,'PayPal','checkout',$5) ON CONFLICT (paypal_order_id) WHERE paypal_order_id IS NOT NULL DO NOTHING RETURNING id`,
            [req.user.discordId, p ? p.id : null, plan, amount == null ? null : String(amount), orderId]);

        let delivered = null;
        if (ins.rows.length) {           // أول مرة نعالج هذا الطلب
            if (plan) {
                delivered = await grantRoleToUser(req.user.discordId, plan);
                if (delivered) await sendDMToUser(req.user.discordId, plan);
            }
            await sendLogToDiscord(req.user.discordId, plan || (p ? p.title : "منتج"), amount, "PayPal (موقع)");
        }
        res.json({ success: true, productId: p ? p.id : null, productTitle: p ? p.title : "", plan, roleGranted: delivered, alreadyProcessed: !ins.rows.length });
    } catch (err) { console.error("capture error:", err); res.status(500).json({ success: false, message: "تعذّر تأكيد الدفع، تواصل معنا وسنؤكده يدوياً" }); }
});

app.listen(process.env.PORT || 3000, () => console.log("✅ Backend running"));