import { AwsClient } from 'aws4fetch';

export interface Env {
  ASSETS: { fetch: (request: Request) => Promise<Response> };
  TREZZY_KV?: KVNamespace;
  SUPABASE_URL: string;
  SUPABASE_SECRET_KEY?: string;
  SUPABASE_SERVICE_ROLE_KEY?: string;
  RESEND_API_KEY?: string;
  RESEND_FROM_EMAIL?: string;
  R2_ACCOUNT_ID: string;
  R2_ACCESS_KEY_ID: string;
  R2_SECRET_ACCESS_KEY: string;
  R2_PRIVATE_BUCKET_NAME: string;
  MEMBER_ACCESS_SECRET: string;
  R2_PUBLIC_URL: string;
  ALLOWED_ORIGINS?: string; // Opcional: "https://trezzyimpressao3d.shop,https://dashboard.trezzy.workers.dev"
}

type PlanTier = 'teste' | 'premium' | 'vip';

const PLAN_CONFIG: Record<PlanTier, { name: string; credits: number; isVip: boolean; prefix: string }> = {
  teste: { name: 'Teste (10 Downloads)', credits: 10, isVip: false, prefix: 'TRZ-TEST' },
  premium: { name: 'Premium (50 Downloads)', credits: 50, isVip: false, prefix: 'TRZ-PRO' },
  vip: { name: 'VIP (ALL Downloads + Updates)', credits: 0, isVip: true, prefix: 'TRZ-VIP' },
};

const SECURITY_HEADERS: Record<string, string> = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
};

function getCorsHeaders(request: Request, env: Env): Record<string, string> {
  const origin = request.headers.get('Origin') || '';
  const allowedList = (env.ALLOWED_ORIGINS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  let allowOrigin = '*';
  if (allowedList.length > 0) {
    allowOrigin = allowedList.includes(origin) ? origin : allowedList[0];
  } else if (origin) {
    allowOrigin = origin;
  }

  return {
    'Access-Control-Allow-Origin': allowOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Vary': 'Origin',
    ...SECURITY_HEADERS,
  };
}

function slugifyTopico(topico: string): string {
  return topico
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
}

// Comparação em tempo constante contra Timing Attacks
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

// PBKDF2 com 100.000 iterações e salt único por usuário (com fallback legado)
async function derivarSenhaPBKDF2(password: string, saltHex: string): Promise<string> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, [
    'deriveBits',
  ]);
  const saltBytes = new Uint8Array(saltHex.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16)));
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: saltBytes, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    256
  );
  const hashHex = Array.from(new Uint8Array(bits))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return `pbkdf2$${saltHex}$${hashHex}`;
}

async function hashSenhaSegura(password: string): Promise<string> {
  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  const saltHex = Array.from(saltBytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return derivarSenhaPBKDF2(password, saltHex);
}

async function hashLegadoSHA256(password: string): Promise<string> {
  const data = new TextEncoder().encode(`trezzy_salt_2026_${password}`);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function verificarSenhaUsuario(
  password: string,
  storedHash: string
): Promise<{ valid: boolean; needsUpgrade: boolean }> {
  if (storedHash.startsWith('pbkdf2$')) {
    const parts = storedHash.split('$');
    if (parts.length !== 3) return { valid: false, needsUpgrade: false };
    const candidate = await derivarSenhaPBKDF2(password, parts[1]);
    return { valid: timingSafeEqual(candidate, storedHash), needsUpgrade: false };
  }
  const legacy = await hashLegadoSHA256(password);
  const ok = timingSafeEqual(legacy, storedHash);
  return { valid: ok, needsUpgrade: ok };
}

// Token HMAC-SHA256 assinado e com expiração (nunca expõe user.id puro como chave de acesso)
async function assinarHMAC(payload: string, secret: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(payload));
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function gerarTokenMembro(userId: string, env: Env): Promise<string> {
  const exp = Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7; // 7 dias
  const payload = `${userId}.${exp}`;
  const sig = await assinarHMAC(payload, env.MEMBER_ACCESS_SECRET || 'trezzy_fallback_secret');
  return `${payload}.${sig}`;
}

async function validarTokenMembro(request: Request, env: Env): Promise<string | null> {
  const raw = (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '').trim();
  if (!raw) return null;

  const parts = raw.split('.');
  if (parts.length !== 3) return null;

  const [userId, expStr, sig] = parts;
  const exp = Number(expStr);
  if (!userId || !exp || Math.floor(Date.now() / 1000) > exp) return null;

  const expectedSig = await assinarHMAC(
    `${userId}.${expStr}`,
    env.MEMBER_ACCESS_SECRET || 'trezzy_fallback_secret'
  );
  return timingSafeEqual(sig, expectedSig) ? userId : null;
}

async function getAdminPassword(env: Env): Promise<string> {
  if (env.TREZZY_KV) {
    const custom = await env.TREZZY_KV.get('ADMIN_CUSTOM_PASSWORD');
    if (custom) return custom;
  }
  return env.MEMBER_ACCESS_SECRET || 'trezzy2026';
}

async function gerarTokenSessaoAdmin(adminPass: string, env: Env): Promise<string> {
  const exp = Math.floor(Date.now() / 1000) + 60 * 60 * 12; // 12 horas
  const payload = `admin.${exp}`;
  const sig = await assinarHMAC(payload, `${adminPass}_${env.MEMBER_ACCESS_SECRET || ''}`);
  return `${payload}.${sig}`;
}

async function validarSessaoAdmin(request: Request, env: Env): Promise<boolean> {
  const raw = (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '').trim();
  const parts = raw.split('.');
  if (parts.length !== 3 || parts[0] !== 'admin') return false;

  const exp = Number(parts[1]);
  if (!exp || Math.floor(Date.now() / 1000) > exp) return false;

  const adminPass = await getAdminPassword(env);
  const expectedSig = await assinarHMAC(
    `admin.${parts[1]}`,
    `${adminPass}_${env.MEMBER_ACCESS_SECRET || ''}`
  );
  return timingSafeEqual(parts[2], expectedSig);
}

// Rate Limiter genérico via KV
async function checkRateLimit(
  env: Env,
  key: string,
  maxHits: number,
  windowSeconds: number
): Promise<{ allowed: boolean; remaining: number }> {
  if (!env.TREZZY_KV) return { allowed: true, remaining: maxHits };
  const current = Number((await env.TREZZY_KV.get(key)) || '0');
  if (current >= maxHits) return { allowed: false, remaining: 0 };
  await env.TREZZY_KV.put(key, String(current + 1), { expirationTtl: windowSeconds });
  return { allowed: true, remaining: Math.max(0, maxHits - (current + 1)) };
}

function getSbKey(env: Env): string {
  return (env.SUPABASE_SECRET_KEY || env.SUPABASE_SERVICE_ROLE_KEY || '').trim();
}

async function sbFetch(env: Env, path: string, init: RequestInit = {}): Promise<Response> {
  const baseUrl = (env.SUPABASE_URL || '').trim().replace(/\/+$/, '');
  const key = getSbKey(env);

  if (!baseUrl || !key) {
    return new Response(
      JSON.stringify({ message: 'Configuração de banco ausente no servidor.' }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }

  return fetch(`${baseUrl}/rest/v1/${path}`, {
    ...init,
    headers: {
      apikey: key,
      Authorization: `Bearer ${key}`,
      'Content-Type': 'application/json',
      ...(init.headers || {}),
    },
  });
}

function gerarCodigo6DigitosSeguro(): string {
  const arr = crypto.getRandomValues(new Uint32Array(1));
  return String(100000 + (arr[0] % 900000));
}

async function enviarCodigoResend(
  env: Env,
  toEmail: string,
  name: string,
  code: string
): Promise<{ ok: boolean; error?: string }> {
  if (!env.RESEND_API_KEY) {
    return { ok: false, error: 'Serviço de e-mail não configurado.' };
  }
  const from = env.RESEND_FROM_EMAIL || 'Trezzy 3D <noreply@trezzyimpressao3d.shop>';
  const safeName = name.replace(/[<>&"']/g, '');

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from,
      to: [toEmail],
      subject: `Código de Ativação Trezzy 3D: ${code}`,
      html: `
        <div style="font-family:sans-serif;background:#09090b;color:#f4f4f5;padding:32px;border-radius:12px;max-width:480px;margin:auto;">
          <h2 style="color:#e11d48;margin-bottom:8px;">TREZZY 3D</h2>
          <p>Olá, <strong>${safeName}</strong>!</p>
          <p>Use o código abaixo (válido por 15 minutos) para ativar sua conta:</p>
          <div style="background:#18181b;border:1px solid #27272a;padding:16px;text-align:center;font-size:28px;font-weight:bold;letter-spacing:6px;color:#ffffff;border-radius:8px;margin:20px 0;">
            ${code}
          </div>
          <p style="font-size:12px;color:#a1a1aa;">Se você não solicitou este cadastro, ignore este e-mail.</p>
        </div>
      `,
    }),
  });

  if (!res.ok) {
    console.error('[RESEND_ERROR]', await res.text());
    return { ok: false, error: 'Falha ao disparar e-mail de verificação.' };
  }
  return { ok: true };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const cors = getCorsHeaders(request, env);
    const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }

    // 1. Proxy Catálogo R2
    if (url.pathname === '/api/catalogo' && request.method === 'GET') {
      const base = (
        env.R2_PUBLIC_URL || 'https://pub-9b4a5394ab8f4c7fae42da15591ac8cf.r2.dev'
      ).replace(/\/+$/, '');

      for (const targetUrl of [
        `${base}/stl/index/catalogo_site.json`,
        `${base}/index/catalogo_site.json`,
        `${base}/catalogo_site.json`,
      ]) {
        try {
          const res = await fetch(targetUrl, { cf: { cacheTtl: 60, cacheEverything: true } });
          if (res.ok) {
            return new Response(await res.text(), {
              status: 200,
              headers: {
                'Content-Type': 'application/json; charset=utf-8',
                'Cache-Control': 'no-store',
                ...cors,
              },
            });
          }
        } catch {
          // próximo
        }
      }
      return jsonResponse({ error: 'Catálogo não encontrado.' }, 404, cors);
    }

    // 2. Criar Conta + Proteção Anti-Spam Resend
    if (url.pathname === '/api/auth/register' && request.method === 'POST') {
      try {
        // Máximo 4 tentativas de cadastro por IP a cada hora
        const rl = await checkRateLimit(env, `REG_LIMIT_${clientIp}`, 4, 3600);
        if (!rl.allowed) {
          return jsonResponse(
            { error: 'Muitas solicitações de cadastro. Tente novamente em 1 hora.' },
            429,
            cors
          );
        }

        const body = (await request.json()) as {
          name?: string;
          email?: string;
          password?: string;
          redeemCode?: string;
        };

        const name = (body.name || '').trim().slice(0, 80);
        const email = (body.email || '').trim().toLowerCase();
        const password = (body.password || '').trim();
        const redeemCode = (body.redeemCode || '').trim().toUpperCase();

        if (!name || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 4) {
          return jsonResponse(
            { error: 'Preencha nome, e-mail válido e senha (mínimo 4 caracteres).' },
            400,
            cors
          );
        }

        const existingRes = await sbFetch(
          env,
          `trezzy_users?email=eq.${encodeURIComponent(email)}&select=id,verified`
        );
        if (!existingRes.ok) {
          return jsonResponse({ error: 'Erro interno ao verificar cadastro.' }, 500, cors);
        }

        const existing = (await existingRes.json()) as any[];
        if (existing.length > 0 && existing[0].verified) {
          return jsonResponse({ error: 'Este e-mail já está cadastrado e ativo.' }, 409, cors);
        }

        const password_hash = await hashSenhaSegura(password);
        const code6 = gerarCodigo6DigitosSeguro();
        const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString(); // 15 min
        const usarResend = Boolean(env.RESEND_API_KEY);

        let userId: string;

        if (existing.length > 0 && !existing[0].verified) {
          userId = existing[0].id;
          await sbFetch(env, `trezzy_users?id=eq.${userId}`, {
            method: 'PATCH',
            body: JSON.stringify({
              name,
              password_hash,
              verification_code: code6,
              verification_expires_at: expiresAt,
              verified: !usarResend,
            }),
          });
        } else {
          const createRes = await sbFetch(env, 'trezzy_users', {
            method: 'POST',
            headers: { Prefer: 'return=representation' },
            body: JSON.stringify({
              name,
              email,
              password_hash,
              plan_name: 'Conta Gratuita (1 Teste)',
              credits: 1,
              is_vip: false,
              verified: !usarResend,
              verification_code: usarResend ? code6 : null,
              verification_expires_at: usarResend ? expiresAt : null,
            }),
          });

          if (!createRes.ok) {
            return jsonResponse({ error: 'Não foi possível criar a conta no momento.' }, 500, cors);
          }

          const created = (await createRes.json()) as any[];
          userId = created[0].id;
        }

        if (env.TREZZY_KV) {
          await env.TREZZY_KV.delete(`VERIFY_TRIES_${email}`);
        }

        if (redeemCode) {
          await aplicarCodigoNaConta(env, userId, redeemCode);
        }

        if (usarResend) {
          const mailResult = await enviarCodigoResend(env, email, name, code6);
          if (!mailResult.ok) {
            return jsonResponse(
              { error: 'Conta criada, mas houve falha ao enviar o e-mail de ativação.' },
              500,
              cors
            );
          }
          return jsonResponse(
            {
              requiresVerification: true,
              email,
              message: 'Enviamos um código de 6 dígitos para o seu e-mail!',
            },
            200,
            cors
          );
        }

        const token = await gerarTokenMembro(userId, env);
        return jsonResponse({ token }, 200, cors);
      } catch {
        return jsonResponse({ error: 'Falha inesperada ao registrar.' }, 500, cors);
      }
    }

    // 2.1. Confirmar Código de Ativação (com limite de 5 tentativas e expiração de 15 min)
    if (url.pathname === '/api/auth/verify' && request.method === 'POST') {
      const body = (await request.json()) as { email?: string; code?: string };
      const email = (body.email || '').trim().toLowerCase();
      const code = (body.code || '').trim();

      if (!email || !/^\d{6}$/.test(code)) {
        return jsonResponse({ error: 'Informe o código de 6 dígitos.' }, 400, cors);
      }

      const verifyRl = await checkRateLimit(env, `VERIFY_TRIES_${email}`, 5, 900);
      if (!verifyRl.allowed) {
        await sbFetch(env, `trezzy_users?email=eq.${encodeURIComponent(email)}`, {
          method: 'PATCH',
          body: JSON.stringify({ verification_code: null }),
        });
        return jsonResponse(
          { error: 'Código bloqueado por excesso de tentativas. Refaça o cadastro.' },
          429,
          cors
        );
      }

      const res = await sbFetch(
        env,
        `trezzy_users?email=eq.${encodeURIComponent(email)}&select=id,verification_code,verification_expires_at`
      );
      const rows = res.ok ? ((await res.json()) as any[]) : [];
      const user = rows[0];

      if (!user || !user.verification_code || !timingSafeEqual(user.verification_code, code)) {
        return jsonResponse({ error: 'Código de ativação incorreto.' }, 400, cors);
      }

      if (
        user.verification_expires_at &&
        new Date(user.verification_expires_at).getTime() < Date.now()
      ) {
        return jsonResponse({ error: 'Código expirado. Solicite um novo cadastro.' }, 400, cors);
      }

      await sbFetch(env, `trezzy_users?id=eq.${user.id}`, {
        method: 'PATCH',
        body: JSON.stringify({
          verified: true,
          verification_code: null,
          verification_expires_at: null,
        }),
      });

      if (env.TREZZY_KV) await env.TREZZY_KV.delete(`VERIFY_TRIES_${email}`);

      const token = await gerarTokenMembro(user.id, env);
      return jsonResponse({ token, message: 'Conta ativada com sucesso!' }, 200, cors);
    }

    // 3. Login (Membro ou Admin com Anti-Brute-Force)
    if (url.pathname === '/api/auth/login' && request.method === 'POST') {
      const body = (await request.json()) as {
        email?: string;
        password?: string;
        scope?: 'admin' | 'member';
      };

      const password = (body.password || '').trim();
      const adminPass = await getAdminPassword(env);

      if (body.scope === 'admin') {
        const lockKey = `ADMIN_LOCK_${clientIp}`;
        if (env.TREZZY_KV) {
          const attempts = Number((await env.TREZZY_KV.get(lockKey)) || '0');
          if (attempts >= 5) {
            return jsonResponse(
              { error: 'Muitas tentativas incorretas. Acesso bloqueado por 30 minutos.' },
              429,
              cors
            );
          }
        }

        if (password && timingSafeEqual(password, adminPass)) {
          if (env.TREZZY_KV) await env.TREZZY_KV.delete(lockKey);
          const sessionToken = await gerarTokenSessaoAdmin(adminPass, env);
          return jsonResponse({ role: 'admin', token: sessionToken }, 200, cors);
        }

        if (env.TREZZY_KV) {
          const attempts = Number((await env.TREZZY_KV.get(lockKey)) || '0') + 1;
          await env.TREZZY_KV.put(lockKey, String(attempts), { expirationTtl: 1800 });
          const restantes = Math.max(0, 5 - attempts);
          return jsonResponse(
            {
              error:
                restantes > 0
                  ? `Senha incorreta. Restam ${restantes} tentativa(s).`
                  : 'IP bloqueado por 30 minutos por segurança.',
            },
            401,
            cors
          );
        }

        return jsonResponse({ error: 'Senha administrativa incorreta.' }, 401, cors);
      }

      // Login Membro (máximo 10 tentativas por IP a cada 15 min)
      const loginRl = await checkRateLimit(env, `LOGIN_IP_${clientIp}`, 10, 900);
      if (!loginRl.allowed) {
        return jsonResponse(
          { error: 'Muitas tentativas de login. Aguarde 15 minutos.' },
          429,
          cors
        );
      }

      const email = (body.email || '').trim().toLowerCase();
      if (!email || !password) {
        return jsonResponse({ error: 'Informe e-mail e senha.' }, 400, cors);
      }

      const res = await sbFetch(
        env,
        `trezzy_users?email=eq.${encodeURIComponent(email)}&select=id,password_hash,verified`
      );
      if (!res.ok) {
        return jsonResponse({ error: 'Erro interno ao autenticar.' }, 500, cors);
      }

      const users = (await res.json()) as any[];
      const user = users[0];

      if (!user) {
        return jsonResponse({ error: 'E-mail ou senha incorretos.' }, 401, cors);
      }

      const check = await verificarSenhaUsuario(password, user.password_hash || '');
      if (!check.valid) {
        return jsonResponse({ error: 'E-mail ou senha incorretos.' }, 401, cors);
      }

      // Migração transparente de hash legado SHA-256 para PBKDF2
      if (check.needsUpgrade) {
        const upgradedHash = await hashSenhaSegura(password);
        await sbFetch(env, `trezzy_users?id=eq.${user.id}`, {
          method: 'PATCH',
          body: JSON.stringify({ password_hash: upgradedHash }),
        });
      }

      if (user.verified === false) {
        return jsonResponse(
          {
            requiresVerification: true,
            email,
            error: 'Confirme o código enviado para seu e-mail antes de entrar.',
          },
          403,
          cors
        );
      }

      const token = await gerarTokenMembro(user.id, env);
      return jsonResponse({ role: 'member', token }, 200, cors);
    }

    // 4. Dados da Conta Logada (/api/me)
    if (url.pathname === '/api/me' && request.method === 'GET') {
      const userId = await validarTokenMembro(request, env);
      if (!userId) return jsonResponse({ error: 'Sessão expirada. Faça login novamente.' }, 401, cors);

      const [userRes, histRes] = await Promise.all([
        sbFetch(env, `trezzy_users?id=eq.${encodeURIComponent(userId)}&select=*`),
        sbFetch(
          env,
          `trezzy_user_downloads?user_id=eq.${encodeURIComponent(userId)}&order=downloaded_at.desc&limit=50`
        ),
      ]);

      if (!userRes.ok) return jsonResponse({ error: 'Erro ao carregar perfil.' }, 500, cors);

      const users = (await userRes.json()) as any[];
      if (!users[0]) return jsonResponse({ error: 'Conta não encontrada.' }, 401, cors);

      const u = users[0];
      const history = histRes.ok ? await histRes.json() : [];

      return jsonResponse(
        {
          id: u.id,
          name: u.name,
          email: u.email,
          planName: u.plan_name,
          isVip: u.is_vip,
          credits: u.credits,
          downloadsUsed: u.downloads_used,
          history,
        },
        200,
        cors
      );
    }

    // 5. Resgatar Chave de Plano (/api/redeem)
    if (url.pathname === '/api/redeem' && request.method === 'POST') {
      const userId = await validarTokenMembro(request, env);
      if (!userId) return jsonResponse({ error: 'Sessão expirada. Faça login.' }, 401, cors);

      const redeemRl = await checkRateLimit(env, `REDEEM_${userId}`, 8, 900);
      if (!redeemRl.allowed) {
        return jsonResponse({ error: 'Muitas tentativas de resgate. Aguarde 15 min.' }, 429, cors);
      }

      const body = (await request.json()) as { code?: string };
      const code = (body.code || '').trim().toUpperCase();
      if (!code) return jsonResponse({ error: 'Digite o código da chave.' }, 400, cors);

      const result = await aplicarCodigoNaConta(env, userId, code);
      if (!result.ok) return jsonResponse({ error: result.error }, 400, cors);
      return jsonResponse({ success: true, message: result.message }, 200, cors);
    }

    // 6. Alterar Senha do Usuário
    if (url.pathname === '/api/user/change-password' && request.method === 'POST') {
      const userId = await validarTokenMembro(request, env);
      if (!userId) return jsonResponse({ error: 'Não autenticado.' }, 401, cors);

      const body = (await request.json()) as { newPassword?: string };
      const newPassword = (body.newPassword || '').trim();
      if (newPassword.length < 4) {
        return jsonResponse({ error: 'Mínimo 4 caracteres.' }, 400, cors);
      }

      const password_hash = await hashSenhaSegura(newPassword);
      await sbFetch(env, `trezzy_users?id=eq.${encodeURIComponent(userId)}`, {
        method: 'PATCH',
        body: JSON.stringify({ password_hash }),
      });

      return jsonResponse({ success: true }, 200, cors);
    }

    // 6.1 Alterar Senha Administrativa
    if (url.pathname === '/api/auth/change-password' && request.method === 'POST') {
      if (!(await validarSessaoAdmin(request, env))) {
        return jsonResponse({ error: 'Acesso negado.' }, 403, cors);
      }

      const body = (await request.json()) as { newPassword?: string };
      const newPass = (body.newPassword || '').trim();
      if (newPass.length < 6) {
        return jsonResponse({ error: 'Mínimo de 6 caracteres.' }, 400, cors);
      }

      if (!env.TREZZY_KV) {
        return jsonResponse({ error: 'Binding TREZZY_KV ausente.' }, 500, cors);
      }

      await env.TREZZY_KV.put('ADMIN_CUSTOM_PASSWORD', newPass);
      const newSessionToken = await gerarTokenSessaoAdmin(newPass, env);
      return jsonResponse({ success: true, token: newSessionToken }, 200, cors);
    }

    // 7. Painel Admin
    if (url.pathname === '/api/admin/overview') {
      if (!(await validarSessaoAdmin(request, env))) {
        return jsonResponse({ error: 'Acesso negado.' }, 403, cors);
      }

      const [codesRes, usersRes] = await Promise.all([
        sbFetch(env, 'trezzy_redeem_codes?order=created_at.desc'),
        sbFetch(
          env,
          'trezzy_users?select=id,name,email,plan_name,is_vip,credits,downloads_used,created_at&order=created_at.desc'
        ),
      ]);

      return jsonResponse(
        {
          codes: codesRes.ok ? await codesRes.json() : [],
          users: usersRes.ok ? await usersRes.json() : [],
        },
        200,
        cors
      );
    }

    if (url.pathname === '/api/admin/codes') {
      if (!(await validarSessaoAdmin(request, env))) {
        return jsonResponse({ error: 'Acesso negado.' }, 403, cors);
      }

      if (request.method === 'POST') {
        const body = (await request.json()) as { label?: string; plan?: PlanTier };
        const planKey: PlanTier = body.plan && PLAN_CONFIG[body.plan] ? body.plan : 'teste';
        const cfg = PLAN_CONFIG[planKey];
        const randomPart = crypto.randomUUID().split('-')[0].toUpperCase();
        const code = `${cfg.prefix}-${randomPart}`;

        const res = await sbFetch(env, 'trezzy_redeem_codes', {
          method: 'POST',
          headers: { Prefer: 'return=representation' },
          body: JSON.stringify({
            code,
            label: (body.label || 'Cliente').trim(),
            plan: planKey,
            plan_name: cfg.name,
            credits_amount: cfg.credits,
            is_vip: cfg.isVip,
          }),
        });

        if (!res.ok) {
          return jsonResponse({ error: 'Erro ao salvar chave.' }, 500, cors);
        }

        const rows = (await res.json()) as any[];
        return jsonResponse({ code: rows[0] }, 200, cors);
      }

      if (request.method === 'DELETE') {
        const code = url.searchParams.get('code');
        if (code) {
          await sbFetch(env, `trezzy_redeem_codes?code=eq.${encodeURIComponent(code)}`, {
            method: 'DELETE',
          });
        }
        return jsonResponse({ success: true }, 200, cors);
      }
    }

    // 8. Download Atômico Protegido (Zero Race Condition + Estorno Automático)
    if (url.pathname === '/api/download' && request.method === 'POST') {
      const userId = await validarTokenMembro(request, env);
      if (!userId) return jsonResponse({ error: 'Sessão expirada. Faça login.' }, 401, cors);

      try {
        const body = (await request.json()) as {
          arquivo?: string;
          caminho_relativo?: string;
          topico?: string;
        };

        const rawPath = body.caminho_relativo || body.arquivo;
        if (!rawPath) return jsonResponse({ error: 'Arquivo inválido.' }, 400, cors);

        // Débito atômico no PostgreSQL antes de gerar a URL assinada
        const rpcRes = await sbFetch(env, 'rpc/consumir_credito_download', {
          method: 'POST',
          body: JSON.stringify({ p_user_id: userId }),
        });

        if (!rpcRes.ok) {
          return jsonResponse({ error: 'Erro ao validar saldo de downloads.' }, 500, cors);
        }

        const autorizado = (await rpcRes.json()) as boolean;
        if (!autorizado) {
          return jsonResponse(
            { error: 'Seus créditos acabaram! Resgate uma chave na aba Meu Plano.' },
            403,
            cors
          );
        }

        const safeFilename = rawPath.replace(/^(\.\.(\/|\\|$))+/, '').replace(/^\/+/, '');
        const onlyFilename = safeFilename.split('/').pop() || safeFilename;
        const topicoSlug = body.topico ? slugifyTopico(body.topico) : '';

        const r2 = new AwsClient({
          accessKeyId: env.R2_ACCESS_KEY_ID,
          secretAccessKey: env.R2_SECRET_ACCESS_KEY,
          service: 's3',
          region: 'auto',
        });

        const baseBucketUrl = `https://${env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com/${env.R2_PRIVATE_BUCKET_NAME}`;

        const candidatos = Array.from(
          new Set(
            [
              safeFilename,
              `stl/${safeFilename}`,
              topicoSlug ? `arquivos/${topicoSlug}/${onlyFilename}` : '',
              topicoSlug ? `stl/arquivos/${topicoSlug}/${onlyFilename}` : '',
              `arquivos/${onlyFilename}`,
              `stl/arquivos/${onlyFilename}`,
            ].filter(Boolean)
          )
        );

        let keyEncontrada: string | null = null;
        for (const candidato of candidatos) {
          const encodedKey = candidato.split('/').map((p) => encodeURIComponent(p)).join('/');
          const signedHead = await r2.sign(
            new Request(`${baseBucketUrl}/${encodedKey}`, { method: 'HEAD' })
          );
          if ((await fetch(signedHead)).ok) {
            keyEncontrada = encodedKey;
            break;
          }
        }

        if (!keyEncontrada) {
          const listUrl = new URL(baseBucketUrl);
          listUrl.searchParams.set('list-type', '2');
          listUrl.searchParams.set('max-keys', '1000');

          const signedList = await r2.sign(new Request(listUrl.toString(), { method: 'GET' }));
          const listRes = await fetch(signedList);

          if (listRes.ok) {
            const xml = await listRes.text();
            const keyMatches = [...xml.matchAll(/<Key>(.*?)<\/Key>/g)].map((m) => m[1]);
            const foundRawKey = keyMatches.find(
              (k) => k === onlyFilename || k.endsWith(`/${onlyFilename}`)
            );

            if (foundRawKey) {
              keyEncontrada = foundRawKey
                .split('/')
                .map((part) => encodeURIComponent(part))
                .join('/');
            }
          }
        }

        if (!keyEncontrada) {
          // Estorna automaticamente o crédito se o arquivo não existir no R2
          await sbFetch(env, 'rpc/estornar_credito_download', {
            method: 'POST',
            body: JSON.stringify({ p_user_id: userId }),
          });
          return jsonResponse({ error: `Arquivo "${onlyFilename}" não encontrado.` }, 404, cors);
        }

        await sbFetch(env, 'trezzy_user_downloads', {
          method: 'POST',
          body: JSON.stringify({
            user_id: userId,
            arquivo: onlyFilename,
            topico: body.topico || 'Geral',
          }),
        });

        const endpoint = new URL(`${baseBucketUrl}/${keyEncontrada}`);
        endpoint.searchParams.set('X-Amz-Expires', '300');
        endpoint.searchParams.set(
          'response-content-disposition',
          `attachment; filename="${encodeURIComponent(onlyFilename)}"`
        );

        const signedRequest = await r2.sign(
          new Request(endpoint.toString(), { method: 'GET' }),
          { aws: { signQuery: true } }
        );

        return jsonResponse({ url: signedRequest.url }, 200, cors);
      } catch (err) {
        console.error('[DOWNLOAD_ERROR]', err);
        await sbFetch(env, 'rpc/estornar_credito_download', {
          method: 'POST',
          body: JSON.stringify({ p_user_id: userId }),
        });
        return jsonResponse({ error: 'Erro ao processar download. Crédito preservado.' }, 500, cors);
      }
    }

    const assetResponse = await env.ASSETS.fetch(request);
    const newHeaders = new Headers(assetResponse.headers);
    Object.entries(SECURITY_HEADERS).forEach(([k, v]) => newHeaders.set(k, v));
    return new Response(assetResponse.body, {
      status: assetResponse.status,
      statusText: assetResponse.statusText,
      headers: newHeaders,
    });
  },
};

async function aplicarCodigoNaConta(
  env: Env,
  userId: string,
  code: string
): Promise<{ ok: boolean; error?: string; message?: string }> {
  const codeRes = await sbFetch(
    env,
    `trezzy_redeem_codes?code=eq.${encodeURIComponent(code)}&select=*`
  );
  if (!codeRes.ok) {
    return { ok: false, error: 'Erro ao validar chave no banco de dados.' };
  }

  const codes = (await codeRes.json()) as any[];
  const record = codes[0];

  if (!record) return { ok: false, error: 'Chave inválida ou inexistente.' };
  if (record.redeemed_by) return { ok: false, error: 'Esta chave já foi utilizada.' };

  // Trava otimista: só marca como resgatada se redeemed_by ainda for NULL
  const lockCodeRes = await sbFetch(
    env,
    `trezzy_redeem_codes?code=eq.${encodeURIComponent(code)}&redeemed_by=is.null`,
    {
      method: 'PATCH',
      headers: { Prefer: 'return=representation' },
      body: JSON.stringify({
        redeemed_by: userId,
        redeemed_at: new Date().toISOString(),
      }),
    }
  );

  const lockedRows = lockCodeRes.ok ? ((await lockCodeRes.json()) as any[]) : [];
  if (lockedRows.length === 0) {
    return { ok: false, error: 'Esta chave acabou de ser utilizada.' };
  }

  const userRes = await sbFetch(env, `trezzy_users?id=eq.${encodeURIComponent(userId)}&select=*`);
  const users = (await userRes.json()) as any[];
  const user = users[0];
  if (!user) return { ok: false, error: 'Usuário não encontrado.' };

  const updatedCredits = (user.credits || 0) + (record.credits_amount || 0);
  const updatedVip = Boolean(user.is_vip || record.is_vip);

  await sbFetch(env, `trezzy_users?id=eq.${encodeURIComponent(userId)}`, {
    method: 'PATCH',
    body: JSON.stringify({
      plan_name: record.plan_name,
      credits: updatedCredits,
      is_vip: updatedVip,
    }),
  });

  return {
    ok: true,
    message: `Plano "${record.plan_name}" ativado com sucesso na sua conta!`,
  };
}

function jsonResponse(
  data: unknown,
  status = 200,
  extraHeaders: Record<string, string> = {}
): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...extraHeaders },
  });
}
