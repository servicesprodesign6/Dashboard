import { AwsClient } from 'aws4fetch';

export interface Env {
  ASSETS: { fetch: (request: Request) => Promise<Response> };
  TREZZY_KV?: KVNamespace;
  SUPABASE_URL: string;
  SUPABASE_SERVICE_ROLE_KEY: string;
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

async function sbFetch(env: Env, path: string, init: RequestInit = {}): Promise<Response> {
  const baseUrl = env.SUPABASE_URL.replace(/\/+$/, '');
  return fetch(`${baseUrl}/rest/v1/${path}`, {
    ...init,
    headers: {
      apikey: env.SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
      'Content-Type': 'application/json',
      ...(init.headers || {}),
    },
  });
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

    // 2. Criar Conta de Usuário (E-mail + Senha)
    if (url.pathname === '/api/auth/register' && request.method === 'POST') {
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

      // Verifica se e-mail já existe
      const existingRes = await sbFetch(
        env,
        `trezzy_users?email=eq.${encodeURIComponent(email)}&select=id`
      );
      const existing = (await existingRes.json()) as { id: string }[];
      if (existing.length > 0) {
        return jsonResponse({ error: 'Este e-mail já possui uma conta cadastrada.' }, 409);
      }

      const password_hash = await hashPassword(password);

      // Cria usuário (1 crédito grátis de boas-vindas se não informar chave)
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
        }),
      });

      if (!createRes.ok) {
        return jsonResponse({ error: 'Erro ao criar conta no banco de dados.' }, 500);
      }

      const createdUsers = (await createRes.json()) as any[];
      const user = createdUsers[0];

      // Se o usuário já colocou uma chave no cadastro, resgata automaticamente
      if (redeemCode) {
        await aplicarCodigoNaConta(env, user.id, redeemCode);
      }

      return jsonResponse({
        token: user.id,
        message: 'Conta criada com sucesso!',
      });
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
        return jsonResponse({ error: 'Informe seu e-mail e senha.' }, 400);
      }

      const password_hash = await hashPassword(password);
      const res = await sbFetch(
        env,
        `trezzy_users?email=eq.${encodeURIComponent(email)}&password_hash=eq.${password_hash}&select=*`
      );
      const users = (await res.json()) as any[];

      if (!users[0]) {
        return jsonResponse({ error: 'E-mail ou senha incorretos.' }, 401);
      }

      return jsonResponse({
        role: 'member',
        token: users[0].id,
      });
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

      const users = (await userRes.json()) as any[];
      if (!users[0]) return jsonResponse({ error: 'Conta não encontrada.' }, 401);

      const u = users[0];
      const history = await histRes.json();

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

    // 5. Resgatar Chave de Uso Único na Conta (/api/redeem)
    if (url.pathname === '/api/redeem' && request.method === 'POST') {
      const userId = (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '').trim();
      if (!userId) return jsonResponse({ error: 'Faça login primeiro.' }, 401);

      const body = (await request.json()) as { code?: string };
      const code = (body.code || '').trim().toUpperCase();
      if (!code) return jsonResponse({ error: 'Digite o código da chave.' }, 400);

      const result = await aplicarCodigoNaConta(env, userId, code);
      if (!result.ok) {
        return jsonResponse({ error: result.error }, 400);
      }
      return jsonResponse({ success: true, message: result.message });
    }

    // 6. Alterar Senha do Próprio Usuário
    if (url.pathname === '/api/user/change-password' && request.method === 'POST') {
      const userId = (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '').trim();
      if (!userId) return jsonResponse({ error: 'Não autenticado.' }, 401);

      const body = (await request.json()) as { newPassword?: string };
      const newPassword = (body.newPassword || '').trim();
      if (newPassword.length < 4) {
        return jsonResponse({ error: 'A nova senha deve ter pelo menos 4 caracteres.' }, 400);
      }

      const password_hash = await hashPassword(newPassword);
      await sbFetch(env, `trezzy_users?id=eq.${encodeURIComponent(userId)}`, {
        method: 'PATCH',
        body: JSON.stringify({ password_hash }),
      });

      return jsonResponse({ success: true });
    }

    // 7. Painel Admin: Gerar / Listar Chaves + Listar Usuários
    if (url.pathname === '/api/admin/overview') {
      const token = (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '').trim();
      if (token !== (await getAdminPassword(env))) {
        return jsonResponse({ error: 'Acesso negado.' }, 403);
      }

      const [codesRes, usersRes] = await Promise.all([
        sbFetch(env, 'trezzy_redeem_codes?order=created_at.desc'),
        sbFetch(env, 'trezzy_users?select=id,name,email,plan_name,is_vip,credits,downloads_used,created_at&order=created_at.desc'),
      ]);

      return jsonResponse({
        codes: await codesRes.json(),
        users: await usersRes.json(),
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

    // 8. Download Protegido por Conta de Usuário
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
            { error: 'Seus créditos acabaram! Resgate uma nova chave na aba Meu Plano.' },
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
          const signedHead = await r2.sign(new Request(`${baseBucketUrl}/${encodedKey}`, { method: 'HEAD' }));
          if ((await fetch(signedHead)).ok) {
            keyEncontrada = encodedKey;
            break;
          }
        }

        if (!keyEncontrada) {
          return jsonResponse({ error: `Arquivo "${onlyFilename}" não encontrado no R2.` }, 404);
        }

        // Desconta 1 crédito (se não for VIP) e salva no histórico do usuário
        const newCredits = user.is_vip ? user.credits : Math.max(0, user.credits - 1);
        const newDownloadsUsed = (user.downloads_used || 0) + 1;

        await Promise.all([
          sbFetch(env, `trezzy_users?id=eq.${encodeURIComponent(userId)}`, {
            method: 'PATCH',
            body: JSON.stringify({
              credits: newCredits,
              downloads_used: newDownloadsUsed,
            }),
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
