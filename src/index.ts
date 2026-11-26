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
}

type PlanTier = 'teste' | 'premium' | 'vip';

const PLAN_CONFIG: Record<PlanTier, { name: string; credits: number; isVip: boolean; prefix: string }> = {
  teste: { name: 'Teste (10 Downloads)', credits: 10, isVip: false, prefix: 'TRZ-TEST' },
  premium: { name: 'Premium (50 Downloads)', credits: 50, isVip: false, prefix: 'TRZ-PRO' },
  vip: { name: 'VIP (ALL Downloads + Updates)', credits: 0, isVip: true, prefix: 'TRZ-VIP' },
};

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function slugifyTopico(topico: string): string {
  return topico
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
}

async function hashPassword(password: string): Promise<string> {
  const data = new TextEncoder().encode(`trezzy_salt_2026_${password}`);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function getAdminPassword(env: Env): Promise<string> {
  if (env.TREZZY_KV) {
    const custom = await env.TREZZY_KV.get('ADMIN_CUSTOM_PASSWORD');
    if (custom) return custom;
  }
  return env.MEMBER_ACCESS_SECRET || 'trezzy2026';
}

function getSbKey(env: Env): string {
  return (env.SUPABASE_SECRET_KEY || env.SUPABASE_SERVICE_ROLE_KEY || '').trim();
}

async function sbFetch(env: Env, path: string, init: RequestInit = {}): Promise<Response> {
  const baseUrl = (env.SUPABASE_URL || '').trim().replace(/\/+$/, '');
  const key = getSbKey(env);

  if (!baseUrl || !key) {
    return new Response(
      JSON.stringify({ message: 'Variáveis SUPABASE_URL ou SUPABASE_SECRET_KEY ausentes no Worker.' }),
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

async function enviarCodigoResend(
  env: Env,
  toEmail: string,
  name: string,
  code: string
): Promise<{ ok: boolean; error?: string }> {
  if (!env.RESEND_API_KEY) {
    return { ok: false, error: 'RESEND_API_KEY não configurada.' };
  }
  const from = env.RESEND_FROM_EMAIL || 'Trezzy 3D <onboarding@resend.dev>';

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
          <p>Olá, <strong>${name}</strong>!</p>
          <p>Use o código abaixo para ativar sua conta e liberar seu acesso à biblioteca:</p>
          <div style="background:#18181b;border:1px solid #27272a;padding:16px;text-align:center;font-size:28px;font-weight:bold;letter-spacing:6px;color:#ffffff;border-radius:8px;margin:20px 0;">
            ${code}
          </div>
          <p style="font-size:12px;color:#a1a1aa;">Se você não solicitou este cadastro, ignore este e-mail.</p>
        </div>
      `,
    }),
  });

  if (!res.ok) {
    const detail = await res.text();
    return { ok: false, error: detail };
  }

  return { ok: true };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
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
                ...corsHeaders,
              },
            });
          }
        } catch {
          // próximo
        }
      }
      return jsonResponse({ error: 'Catálogo não encontrado.' }, 404);
    }

    // 2. Criar Conta + Envio de Código via Resend
    if (url.pathname === '/api/auth/register' && request.method === 'POST') {
      try {
        const body = (await request.json()) as {
          name?: string;
          email?: string;
          password?: string;
          redeemCode?: string;
        };

        const name = (body.name || '').trim();
        const email = (body.email || '').trim().toLowerCase();
        const password = (body.password || '').trim();
        const redeemCode = (body.redeemCode || '').trim().toUpperCase();

        if (!name || !email || password.length < 4) {
          return jsonResponse({ error: 'Preencha nome, e-mail e senha (mínimo 4 caracteres).' }, 400);
        }

        const existingRes = await sbFetch(
          env,
          `trezzy_users?email=eq.${encodeURIComponent(email)}&select=id,verified`
        );

        if (!existingRes.ok) {
          const errText = await existingRes.text();
          return jsonResponse(
            { error: `Erro ao consultar Supabase (${existingRes.status}): ${errText}` },
            500
          );
        }

        const existing = (await existingRes.json()) as any[];
        if (existing.length > 0 && existing[0].verified) {
          return jsonResponse({ error: 'Este e-mail já está cadastrado e ativo.' }, 409);
        }

        const password_hash = await hashPassword(password);
        const code6 = String(Math.floor(100000 + Math.random() * 900000));
        const usarResend = Boolean(env.RESEND_API_KEY);

        let userId: string;

        if (existing.length > 0 && !existing[0].verified) {
          userId = existing[0].id;
          const updRes = await sbFetch(env, `trezzy_users?id=eq.${userId}`, {
            method: 'PATCH',
            body: JSON.stringify({
              name,
              password_hash,
              verification_code: code6,
              verified: !usarResend,
            }),
          });
          if (!updRes.ok) {
            const errDetail = await updRes.text();
            return jsonResponse({ error: `Erro Supabase (${updRes.status}): ${errDetail}` }, 500);
          }
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
            }),
          });

          if (!createRes.ok) {
            const errDetail = await createRes.text();
            console.error('[SUPABASE_REGISTER_ERROR]', createRes.status, errDetail);
            return jsonResponse(
              { error: `Erro Supabase (${createRes.status}): ${errDetail}` },
              500
            );
          }

          const created = (await createRes.json()) as any[];
          userId = created[0].id;
        }

        if (redeemCode) {
          await aplicarCodigoNaConta(env, userId, redeemCode);
        }

        if (usarResend) {
          const mailResult = await enviarCodigoResend(env, email, name, code6);
          if (!mailResult.ok) {
            return jsonResponse(
              { error: `Conta criada, mas falhou o envio do e-mail Resend: ${mailResult.error}` },
              500
            );
          }
          return jsonResponse({
            requiresVerification: true,
            email,
            message: 'Enviamos um código de 6 dígitos para o seu e-mail!',
          });
        }

        return jsonResponse({ token: userId });
      } catch (err: any) {
        return jsonResponse({ error: `Falha inesperada: ${err?.message || err}` }, 500);
      }
    }

    // 2.1. Confirmar Código de Ativação enviado pelo Resend
    if (url.pathname === '/api/auth/verify' && request.method === 'POST') {
      const body = (await request.json()) as { email?: string; code?: string };
      const email = (body.email || '').trim().toLowerCase();
      const code = (body.code || '').trim();

      const res = await sbFetch(
        env,
        `trezzy_users?email=eq.${encodeURIComponent(email)}&verification_code=eq.${encodeURIComponent(code)}&select=id`
      );
      if (!res.ok) {
        const errDetail = await res.text();
        return jsonResponse({ error: `Erro Supabase (${res.status}): ${errDetail}` }, 500);
      }

      const rows = (await res.json()) as any[];
      if (!rows[0]) {
        return jsonResponse({ error: 'Código de ativação incorreto.' }, 400);
      }

      await sbFetch(env, `trezzy_users?id=eq.${rows[0].id}`, {
        method: 'PATCH',
        body: JSON.stringify({ verified: true, verification_code: null }),
      });

      return jsonResponse({ token: rows[0].id, message: 'Conta ativada com sucesso!' });
    }

    // 3. Login (Usuário E-mail/Senha ou Admin)
    if (url.pathname === '/api/auth/login' && request.method === 'POST') {
      const body = (await request.json()) as {
        email?: string;
        password?: string;
        scope?: 'admin' | 'member';
      };

      const password = (body.password || '').trim();
      const adminPass = await getAdminPassword(env);

      if (body.scope === 'admin') {
        if (password && password === adminPass) {
          return jsonResponse({ role: 'admin', token: password });
        }
        return jsonResponse({ error: 'Senha administrativa incorreta.' }, 401);
      }

      const email = (body.email || '').trim().toLowerCase();
      if (!email || !password) {
        return jsonResponse({ error: 'Informe e-mail e senha.' }, 400);
      }

      const password_hash = await hashPassword(password);
      const res = await sbFetch(
        env,
        `trezzy_users?email=eq.${encodeURIComponent(email)}&password_hash=eq.${password_hash}&select=*`
      );
      if (!res.ok) {
        const errDetail = await res.text();
        return jsonResponse({ error: `Erro Supabase (${res.status}): ${errDetail}` }, 500);
      }

      const users = (await res.json()) as any[];

      if (!users[0]) {
        return jsonResponse({ error: 'E-mail ou senha incorretos.' }, 401);
      }

      if (users[0].verified === false) {
        return jsonResponse(
          {
            requiresVerification: true,
            email,
            error: 'Confirme o código enviado para seu e-mail antes de entrar.',
          },
          403
        );
      }

      return jsonResponse({ role: 'member', token: users[0].id });
    }

    // 4. Dados da Conta Logada (/api/me)
    if (url.pathname === '/api/me' && request.method === 'GET') {
      const userId = (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '').trim();
      if (!userId) return jsonResponse({ error: 'Não autenticado.' }, 401);

      const [userRes, histRes] = await Promise.all([
        sbFetch(env, `trezzy_users?id=eq.${encodeURIComponent(userId)}&select=*`),
        sbFetch(
          env,
          `trezzy_user_downloads?user_id=eq.${encodeURIComponent(userId)}&order=downloaded_at.desc&limit=50`
        ),
      ]);

      if (!userRes.ok) {
        return jsonResponse({ error: 'Erro ao carregar perfil.' }, 500);
      }

      const users = (await userRes.json()) as any[];
      if (!users[0]) return jsonResponse({ error: 'Conta não encontrada.' }, 401);

      const u = users[0];
      const history = histRes.ok ? await histRes.json() : [];

      return jsonResponse({
        id: u.id,
        name: u.name,
        email: u.email,
        planName: u.plan_name,
        isVip: u.is_vip,
        credits: u.credits,
        downloadsUsed: u.downloads_used,
        history,
      });
    }

    // 5. Resgatar Chave de Plano (/api/redeem)
    if (url.pathname === '/api/redeem' && request.method === 'POST') {
      const userId = (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '').trim();
      if (!userId) return jsonResponse({ error: 'Faça login primeiro.' }, 401);

      const body = (await request.json()) as { code?: string };
      const code = (body.code || '').trim().toUpperCase();
      if (!code) return jsonResponse({ error: 'Digite o código da chave.' }, 400);

      const result = await aplicarCodigoNaConta(env, userId, code);
      if (!result.ok) return jsonResponse({ error: result.error }, 400);
      return jsonResponse({ success: true, message: result.message });
    }

    // 6. Alterar Senha do Usuário
    if (url.pathname === '/api/user/change-password' && request.method === 'POST') {
      const userId = (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '').trim();
      if (!userId) return jsonResponse({ error: 'Não autenticado.' }, 401);

      const body = (await request.json()) as { newPassword?: string };
      const newPassword = (body.newPassword || '').trim();
      if (newPassword.length < 4) {
        return jsonResponse({ error: 'Mínimo 4 caracteres.' }, 400);
      }

      const password_hash = await hashPassword(newPassword);
      await sbFetch(env, `trezzy_users?id=eq.${encodeURIComponent(userId)}`, {
        method: 'PATCH',
        body: JSON.stringify({ password_hash }),
      });

      return jsonResponse({ success: true });
    }

    // 6.1 Alterar Senha Administrativa
    if (url.pathname === '/api/auth/change-password' && request.method === 'POST') {
      const authHeader = request.headers.get('Authorization') || '';
      const currentToken = authHeader.replace(/^Bearer\s+/i, '').trim();
      const adminPass = await getAdminPassword(env);

      if (currentToken !== adminPass) {
        return jsonResponse({ error: 'Acesso negado.' }, 403);
      }

      const body = (await request.json()) as { newPassword?: string };
      const newPass = (body.newPassword || '').trim();
      if (newPass.length < 4) {
        return jsonResponse({ error: 'Mínimo de 4 caracteres.' }, 400);
      }

      if (!env.TREZZY_KV) {
        return jsonResponse({ error: 'Binding TREZZY_KV ausente.' }, 500);
      }

      await env.TREZZY_KV.put('ADMIN_CUSTOM_PASSWORD', newPass);
      return jsonResponse({ success: true, token: newPass });
    }

    // 7. Painel Admin
    if (url.pathname === '/api/admin/overview') {
      const token = (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '').trim();
      if (token !== (await getAdminPassword(env))) {
        return jsonResponse({ error: 'Acesso negado.' }, 403);
      }

      const [codesRes, usersRes] = await Promise.all([
        sbFetch(env, 'trezzy_redeem_codes?order=created_at.desc'),
        sbFetch(
          env,
          'trezzy_users?select=id,name,email,plan_name,is_vip,credits,downloads_used,created_at&order=created_at.desc'
        ),
      ]);

      return jsonResponse({
        codes: codesRes.ok ? await codesRes.json() : [],
        users: usersRes.ok ? await usersRes.json() : [],
      });
    }

    if (url.pathname === '/api/admin/codes') {
      const token = (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '').trim();
      if (token !== (await getAdminPassword(env))) {
        return jsonResponse({ error: 'Acesso negado.' }, 403);
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
          const errDetail = await res.text();
          return jsonResponse({ error: `Erro Supabase (${res.status}): ${errDetail}` }, 500);
        }

        const rows = (await res.json()) as any[];
        return jsonResponse({ code: rows[0] });
      }

      if (request.method === 'DELETE') {
        const code = url.searchParams.get('code');
        if (code) {
          await sbFetch(env, `trezzy_redeem_codes?code=eq.${encodeURIComponent(code)}`, {
            method: 'DELETE',
          });
        }
        return jsonResponse({ success: true });
      }
    }

    // 8. Download Protegido por Conta
    if (url.pathname === '/api/download' && request.method === 'POST') {
      try {
        const userId = (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '').trim();
        if (!userId) return jsonResponse({ error: 'Faça login para baixar.' }, 401);

        const userRes = await sbFetch(env, `trezzy_users?id=eq.${encodeURIComponent(userId)}&select=*`);
        const users = (await userRes.json()) as any[];
        const user = users[0];

        if (!user) return jsonResponse({ error: 'Conta inválida.' }, 401);
        if (!user.is_vip && user.credits <= 0) {
          return jsonResponse(
            { error: 'Seus créditos acabaram! Resgate uma chave na aba Meu Plano.' },
            403
          );
        }

        const body = (await request.json()) as {
          arquivo?: string;
          caminho_relativo?: string;
          topico?: string;
        };

        const rawPath = body.caminho_relativo || body.arquivo;
        if (!rawPath) return jsonResponse({ error: 'Arquivo inválido.' }, 400);

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
          return jsonResponse({ error: `Arquivo "${onlyFilename}" não encontrado no R2.` }, 404);
        }

        const newCredits = user.is_vip ? user.credits : Math.max(0, user.credits - 1);
        const newDownloadsUsed = (user.downloads_used || 0) + 1;

        await Promise.all([
          sbFetch(env, `trezzy_users?id=eq.${encodeURIComponent(userId)}`, {
            method: 'PATCH',
            body: JSON.stringify({ credits: newCredits, downloads_used: newDownloadsUsed }),
          }),
          sbFetch(env, 'trezzy_user_downloads', {
            method: 'POST',
            body: JSON.stringify({
              user_id: userId,
              arquivo: onlyFilename,
              topico: body.topico || 'Geral',
            }),
          }),
        ]);

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

        return jsonResponse({ url: signedRequest.url });
      } catch (err) {
        console.error('[DOWNLOAD_ERROR]', err);
        return jsonResponse({ error: 'Erro ao processar download.' }, 500);
      }
    }

    return env.ASSETS.fetch(request);
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

  const userRes = await sbFetch(env, `trezzy_users?id=eq.${encodeURIComponent(userId)}&select=*`);
  const users = (await userRes.json()) as any[];
  const user = users[0];
  if (!user) return { ok: false, error: 'Usuário não encontrado.' };

  const updatedCredits = (user.credits || 0) + (record.credits_amount || 0);
  const updatedVip = Boolean(user.is_vip || record.is_vip);

  await Promise.all([
    sbFetch(env, `trezzy_redeem_codes?code=eq.${encodeURIComponent(code)}`, {
      method: 'PATCH',
      body: JSON.stringify({
        redeemed_by: userId,
        redeemed_at: new Date().toISOString(),
      }),
    }),
    sbFetch(env, `trezzy_users?id=eq.${encodeURIComponent(userId)}`, {
      method: 'PATCH',
      body: JSON.stringify({
        plan_name: record.plan_name,
        credits: updatedCredits,
        is_vip: updatedVip,
      }),
    }),
  ]);

  return {
    ok: true,
    message: `Plano "${record.plan_name}" ativado com sucesso na sua conta!`,
  };
}

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...corsHeaders },
  });
}
