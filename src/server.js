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

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: required(GMAIL_USER, 'GMAIL_USER'),
        pass: required(GMAIL_APP_PASSWORD, 'GMAIL_APP_PASSWORD'),
      },
    });

    await transporter.sendMail({
      from: `CloudNest <${GMAIL_USER}>`,
      to: email,
      subject: 'Verify your CloudNest account',
      html: buildEmailTemplate({ fullName, link: verificationLink, expiresAt }),
      text: `Hi ${fullName}, verify your CloudNest account: ${verificationLink}`,
    });

    res.status(202).json({ status: 'sent', expiresAt });
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

    const result = await databases.listDocuments(
      required(APPWRITE_DATABASE_ID, 'APPWRITE_DATABASE_ID'),
      required(APPWRITE_VERIFICATION_COLLECTION_ID, 'APPWRITE_VERIFICATION_COLLECTION_ID'),
      [
        sdk.Query.equal('userId', userId),
        sdk.Query.equal('secret', secret),
        sdk.Query.equal('type', 'email_verification'),
        sdk.Query.equal('used', false),
        sdk.Query.greaterThan('expire', new Date().toISOString()),
      ],
    );

    if (!result.documents || result.documents.length === 0) {
      return res.redirect(`${APP_URL}/verify-failed?error=invalid_token`);
    }

    const tokenDoc = result.documents[0];
    await users.updateEmailVerification(userId, true);
    await databases.updateDocument(
      required(APPWRITE_DATABASE_ID, 'APPWRITE_DATABASE_ID'),
      required(APPWRITE_VERIFICATION_COLLECTION_ID, 'APPWRITE_VERIFICATION_COLLECTION_ID'),
      tokenDoc.$id,
      { used: true, usedAt: new Date().toISOString() },
    );

    return res.redirect(`${APP_URL}/verify-success`);
  } catch (err) {
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
