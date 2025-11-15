import 'dotenv/config';
import crypto from 'crypto';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import nodemailer from 'nodemailer';
import sdk from 'node-appwrite';

const {
  PORT = 4000,
  BACKEND_BASE_URL,
  APP_URL,
  APPWRITE_ENDPOINT,
  APPWRITE_PROJECT_ID,
  APPWRITE_API_KEY,
  APPWRITE_DATABASE_ID,
  APPWRITE_VERIFICATION_COLLECTION_ID,
  GMAIL_USER,
  GMAIL_APP_PASSWORD,
} = process.env;

function required(value, name) {
  if (!value) {
    throw new Error(`Missing environment variable: ${name}`);
  }
  return value;
}

function createAppwriteClient() {
  return new sdk.Client()
    .setEndpoint(required(APPWRITE_ENDPOINT, 'APPWRITE_ENDPOINT'))
    .setProject(required(APPWRITE_PROJECT_ID, 'APPWRITE_PROJECT_ID'))
    .setKey(required(APPWRITE_API_KEY, 'APPWRITE_API_KEY'));
}

function buildEmailTemplate({ fullName, link, expiresAt }) {
  const prettyDate = new Date(expiresAt).toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
  return `
  <div style="font-family:'Inter',Arial,sans-serif;background:#f4f6fb;padding:32px;">
    <table style="max-width:520px;margin:0 auto;background:#fff;border-radius:24px;padding:32px 40px;box-shadow:0 18px 45px rgba(15,23,42,0.12);border:1px solid #e2e8f0;">
      <tr>
        <td style="text-align:center;">
          <h1 style="margin:0;color:#0f172a;font-size:28px;">CloudNest</h1>
          <p style="margin:4px 0 24px;color:#64748b;font-size:14px;">Secure cloud storage for modern teams</p>
        </td>
      </tr>
      <tr>
        <td style="color:#0f172a;">
          <h2 style="margin:0 0 12px;font-size:22px;">Verify your email</h2>
          <p style="margin:0;color:#475569;font-size:15px;line-height:1.6;">
            Hi ${fullName}, thanks for joining CloudNest. Confirm your email within the next hour to unlock 5&nbsp;GB of encrypted storage.
          </p>
          <div style="text-align:center;margin:32px 0;">
            <a href="${link}" style="display:inline-block;background:#2563eb;color:#fff;padding:14px 32px;border-radius:999px;text-decoration:none;font-weight:600;box-shadow:0 14px 30px rgba(37,99,235,0.25);">
              Verify email address
            </a>
          </div>
          <p style="color:#475569;font-size:14px;line-height:1.6;">
            Or copy this link:<br>
            <a href="${link}" style="color:#2563eb;word-break:break-all;">${link}</a>
          </p>
          <p style="color:#94a3b8;font-size:12px;">This link expires at ${prettyDate}. If you did not request this, you can safely ignore it.</p>
        </td>
      </tr>
      <tr>
        <td style="padding-top:24px;text-align:center;color:#94a3b8;font-size:12px;">
          © ${new Date().getFullYear()} CloudNest · <a href="${APP_URL}" style="color:#94a3b8;">Visit dashboard</a>
        </td>
      </tr>
    </table>
  </div>`;
}

const app = express();
app.use(helmet());
app.use(cors({ origin: APP_URL ? [APP_URL] : '*', credentials: true }));
app.use(morgan('dev'));
app.use(express.json());

app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: Date.now() });
});

app.post('/api/auth/verification/send', async (req, res, next) => {
  try {
    const { userId, email, fullName } = req.body ?? {};
    if (!userId || !email || !fullName) {
      return res.status(400).json({ error: 'userId, email, and fullName are required' });
    }

    const secret = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
    const verificationLink = `${required(BACKEND_BASE_URL, 'BACKEND_BASE_URL')}/api/auth/verification/confirm?userId=${encodeURIComponent(userId)}&secret=${secret}`;

    const client = createAppwriteClient();
    const databases = new sdk.Databases(client);

    await databases.createDocument(
      required(APPWRITE_DATABASE_ID, 'APPWRITE_DATABASE_ID'),
      required(APPWRITE_VERIFICATION_COLLECTION_ID, 'APPWRITE_VERIFICATION_COLLECTION_ID'),
      sdk.ID.unique(),
      {
        userId,
        email,
        fullName,
        secret,
        expire: expiresAt,
        type: 'email_verification',
        used: false,
        usedAt: null,
      },
      [
        sdk.Permission.read(sdk.Role.any()),
        sdk.Permission.write(sdk.Role.any()),
        sdk.Permission.update(sdk.Role.any()),
      ],
    );

    const gmailUser = required(GMAIL_USER, 'GMAIL_USER');
    const gmailPass = required(GMAIL_APP_PASSWORD, 'GMAIL_APP_PASSWORD');
    
    console.log(`[Email] Preparing to send verification email to: ${email}`);
    
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: gmailUser,
        pass: gmailPass,
      },
    });

    // Verify transporter connection
    try {
      await transporter.verify();
      console.log('[Email] Gmail SMTP connection verified successfully');
    } catch (verifyErr) {
      console.error('[Email] Gmail SMTP verification failed:', verifyErr.message);
      throw new Error(`Gmail authentication failed: ${verifyErr.message}. Check GMAIL_USER and GMAIL_APP_PASSWORD in .env`);
    }

    const mailOptions = {
      from: `CloudNest <${gmailUser}>`,
      to: email,
      subject: 'Verify your CloudNest account',
      html: buildEmailTemplate({ fullName, link: verificationLink, expiresAt }),
      text: `Hi ${fullName}, verify your CloudNest account: ${verificationLink}`,
    };

    console.log(`[Email] Sending email to ${email}...`);
    const info = await transporter.sendMail(mailOptions);
    console.log(`[Email] Email sent successfully. MessageId: ${info.messageId}`);
    console.log(`[Email] Verification link: ${verificationLink}`);

    res.status(202).json({ status: 'sent', expiresAt, messageId: info.messageId });
  } catch (err) {
    next(err);
  }
});

app.get('/api/auth/verification/confirm', async (req, res, next) => {
  try {
    const { userId, secret } = req.query ?? {};
    if (!userId || !secret) {
      return res.redirect(`${APP_URL}/verify-failed?error=missing_params`);
    }

    const client = createAppwriteClient();
    const databases = new sdk.Databases(client);
    const users = new sdk.Users(client);

    const databaseId = required(APPWRITE_DATABASE_ID, 'APPWRITE_DATABASE_ID');
    const collectionId = required(APPWRITE_VERIFICATION_COLLECTION_ID, 'APPWRITE_VERIFICATION_COLLECTION_ID');
    const nowIso = new Date().toISOString();

    // Build query parameters manually to avoid body in GET request
    // Format: equal("field","value") or equal("field",false) or greaterThan("field","ISO_DATE")
    const queryParts = [
      `equal("userId","${userId}")`,
      `equal("secret","${secret}")`,
      `equal("type","email_verification")`,
      `equal("used",false)`,
      `greaterThan("expire","${nowIso}")`,
      `limit(1)`,
    ];
    
    // Build query string: queries[0]=...&queries[1]=...
    const queryString = queryParts
      .map((q, i) => `queries[${i}]=${encodeURIComponent(q)}`)
      .join('&');
    
    const apiPath = `/databases/${databaseId}/collections/${collectionId}/documents?${queryString}`;

    // Use client.call directly with GET (no body, minimal headers)
    const result = await client.call('get', apiPath, {}, {});

    const documents = result?.documents || [];
    if (documents.length === 0) {
      console.log(`[Verify] Invalid or expired token for user: ${userId}`);
      return res.redirect(`${APP_URL}/verify-failed?error=invalid_token`);
    }

    const tokenDoc = documents[0];
    console.log(`[Verify] Found valid token for user: ${userId}`);

    // Update email verification status
    await users.updateEmailVerification(userId, true);
    console.log(`[Verify] Email verified for user: ${userId}`);

    // Mark token as used
    await databases.updateDocument(
      databaseId,
      collectionId,
      tokenDoc.$id,
      { used: true, usedAt: nowIso },
    );
    console.log(`[Verify] Token marked as used: ${tokenDoc.$id}`);

    return res.redirect(`${APP_URL}/verify-success`);
  } catch (err) {
    console.error('[Verify] Error:', err.message);
    next(err);
  }
});

app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) {
    return next(err);
  }
  res.status(500).json({ error: 'Internal Server Error', details: err.message });
});

app.listen(PORT, () => {
  console.log(`CloudNest backend listening on port ${PORT}`);
});
