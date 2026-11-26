import { AwsClient } from 'aws4fetch';

export interface Env {
  ASSETS: {
    fetch: (request: Request) => Promise<Response>;
  };
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

interface DbToken {
  code: string;
  label: string;
  plan: PlanTier;
  plan_name: string;
  max_downloads: number | null;
  downloads_used: number;
  active: boolean;
  created_at: string;
  last_used_at: string | null;
}

const PLAN_CONFIG: Record<PlanTier, { name: string; max: number | null; prefix: string }> = {
  teste: { name: 'Teste (10 Downloads)', max: 10, prefix: 'TRZ-TEST' },
  premium: { name: 'Premium (50 Downloads)', max: 50, prefix: 'TRZ-PRO' },
  vip: { name: 'VIP (ALL Downloads + Updates)', max: null, prefix: 'TRZ-VIP' },
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

async function getAdminPassword(env: Env): Promise<string> {
  if (env.TREZZY_KV) {
    const customPass = await env.TREZZY_KV.get('ADMIN_CUSTOM_PASSWORD');
    if (customPass) return customPass;
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

    // 1. Proxy do Catálogo R2
    if (url.pathname === '/api/catalogo' && request.method === 'GET') {
      const base = (
        env.R2_PUBLIC_URL ||
        'https://pub-9b4a5394ab8f4c7fae42da15591ac8cf.r2.dev'
      ).replace(/\/+$/, '');

      const caminhos = [
        `${base}/stl/index/catalogo_site.json`,
        `${base}/index/catalogo_site.json`,
        `${base}/catalogo_site.json`,
      ];

      for (const targetUrl of caminhos) {
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
      return jsonResponse({ error: 'catalogo_site.json não encontrado no R2.' }, 404);
    }

    // 2. Login Separado (Admin vs Membro)
    if (url.pathname === '/api/auth/login' && request.method === 'POST') {
      const body = (await request.json()) as { password?: string; scope?: 'admin' | 'member' };
      const inputPass = (body.password || '').trim();
      const adminPass = await getAdminPassword(env);

      // Login exclusivo do Painel Admin
      if (body.scope === 'admin') {
        if (inputPass && inputPass === adminPass) {
          return jsonResponse({ role: 'admin', token: inputPass });
        }
        return jsonResponse({ error: 'Senha administrativa incorreta.' }, 401);
      }

      // Login da Área de Membros (aceita Admin ou Chave do Supabase)
      if (inputPass && inputPass === adminPass) {
        return jsonResponse({
          role: 'member',
          isAdminPreview: true,
          token: inputPass,
          label: 'Administrador Trezzy',
          planName: 'VIP Admin (Ilimitado)',
          maxDownloads: null,
          downloadsUsed: 0,
        });
      }

      if (!env.SUPABASE_URL || !env.SUPABASE_SERVICE_ROLE_KEY) {
        return jsonResponse({ error: 'Banco de dados Supabase não configurado.' }, 500);
      }

      const res = await sbFetch(
        env,
        `trezzy_tokens?code=eq.${encodeURIComponent(inputPass)}&select=*`
      );
      const rows = (await res.json()) as DbToken[];
      const record = rows[0];

      if (!record || !record.active) {
        return jsonResponse({ error: 'Chave de acesso inválida ou desativada.' }, 401);
      }

      if (record.max_downloads !== null && record.downloads_used >= record.max_downloads) {
        return jsonResponse(
          { error: `Cota de ${record.max_downloads} downloads atingida neste plano.` },
          403
        );
      }

      return jsonResponse({
        role: 'member',
        token: record.code,
        label: record.label,
        plan: record.plan,
        planName: record.plan_name,
        maxDownloads: record.max_downloads,
        downloadsUsed: record.downloads_used,
      });
    }

    // 3. Dados Isolados do Próprio Cliente (Meus Downloads + Cota Atual)
    if (url.pathname === '/api/me' && request.method === 'GET') {
      const authHeader = request.headers.get('Authorization') || '';
      const token = authHeader.replace(/^Bearer\s+/i, '').trim();
      if (!token) return jsonResponse({ error: 'Não autenticado.' }, 401);

      const adminPass = await getAdminPassword(env);
      if (token === adminPass) {
        return jsonResponse({
          label: 'Administrador Trezzy',
          planName: 'VIP Admin (Ilimitado)',
          maxDownloads: null,
          downloadsUsed: 0,
          history: [],
        });
      }

      const [tokRes, histRes] = await Promise.all([
        sbFetch(env, `trezzy_tokens?code=eq.${encodeURIComponent(token)}&select=*`),
        sbFetch(
          env,
          `trezzy_downloads?token_code=eq.${encodeURIComponent(token)}&order=downloaded_at.desc&limit=50`
        ),
      ]);

      const tokens = (await tokRes.json()) as DbToken[];
      if (!tokens[0] || !tokens[0].active) {
        return jsonResponse({ error: 'Sessão inválida.' }, 401);
      }

      const history = await histRes.json();
      return jsonResponse({
        label: tokens[0].label,
        planName: tokens[0].plan_name,
        maxDownloads: tokens[0].max_downloads,
        downloadsUsed: tokens[0].downloads_used,
        history,
      });
    }

    // 4. Alterar Senha Administrativa (Apenas Admin)
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

    // 5. Gestão Administrativa de Chaves no Supabase (Apenas Admin)
    if (url.pathname === '/api/admin/tokens') {
      const authHeader = request.headers.get('Authorization') || '';
      const token = authHeader.replace(/^Bearer\s+/i, '').trim();
      const adminPass = await getAdminPassword(env);

      if (token !== adminPass) {
        return jsonResponse({ error: 'Acesso exclusivo do administrador.' }, 403);
      }

      if (request.method === 'GET') {
        const res = await sbFetch(env, 'trezzy_tokens?order=created_at.desc');
        const tokens = await res.json();
        return jsonResponse({ tokens });
      }

      if (request.method === 'POST') {
        const body = (await request.json()) as { label?: string; plan?: PlanTier };
        const planKey: PlanTier = body.plan && PLAN_CONFIG[body.plan] ? body.plan : 'teste';
        const cfg = PLAN_CONFIG[planKey];
        const randomPart = crypto.randomUUID().split('-')[0].toUpperCase();
        const code = `${cfg.prefix}-${randomPart}`;

        const payload = {
          code,
          label: (body.label || 'Cliente Trezzy 3D').trim(),
          plan: planKey,
          plan_name: cfg.name,
          max_downloads: cfg.max,
          downloads_used: 0,
          active: true,
        };

        const res = await sbFetch(env, 'trezzy_tokens', {
          method: 'POST',
          headers: { Prefer: 'return=representation' },
          body: JSON.stringify(payload),
        });

        if (!res.ok) {
          return jsonResponse({ error: 'Falha ao salvar chave no Supabase.' }, 500);
        }

        const created = (await res.json()) as DbToken[];
        return jsonResponse({ token: created[0] });
      }

      if (request.method === 'DELETE') {
        const code = url.searchParams.get('code');
        if (code) {
          await sbFetch(env, `trezzy_tokens?code=eq.${encodeURIComponent(code)}`, {
            method: 'DELETE',
          });
        }
        return jsonResponse({ success: true });
      }
    }

    // 6. Download Protegido + Registro no Supabase
    if (url.pathname === '/api/download' && request.method === 'POST') {
      try {
        const authHeader = request.headers.get('Authorization') || '';
        const token = authHeader.replace(/^Bearer\s+/i, '').trim();
        if (!token) return jsonResponse({ error: 'Não autorizado.' }, 401);

        const adminPass = await getAdminPassword(env);
        const isAdmin = token === adminPass;
        let memberRecord: DbToken | null = null;

        if (!isAdmin) {
          const res = await sbFetch(
            env,
            `trezzy_tokens?code=eq.${encodeURIComponent(token)}&select=*`
          );
          const rows = (await res.json()) as DbToken[];
          memberRecord = rows[0] || null;

          if (!memberRecord || !memberRecord.active) {
            return jsonResponse({ error: 'Chave inválida ou bloqueada.' }, 403);
          }

          if (
            memberRecord.max_downloads !== null &&
            memberRecord.downloads_used >= memberRecord.max_downloads
          ) {
            return jsonResponse(
              { error: `Limite de ${memberRecord.max_downloads} downloads atingido.` },
              403
            );
          }
        }

        const body = (await request.json()) as {
          arquivo?: string;
          caminho_relativo?: string;
          topico?: string;
        };

        const rawPath = body.caminho_relativo || body.arquivo;
        if (!rawPath || typeof rawPath !== 'string') {
          return jsonResponse({ error: 'Arquivo inválido.' }, 400);
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
          const encodedKey = candidato
            .split('/')
            .map((part) => encodeURIComponent(part))
            .join('/');

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

        // Atualiza cota e salva histórico isolado no Supabase
        let newUsedCount = memberRecord ? memberRecord.downloads_used + 1 : 0;
        if (memberRecord) {
          await Promise.all([
            sbFetch(env, `trezzy_tokens?code=eq.${encodeURIComponent(token)}`, {
              method: 'PATCH',
              body: JSON.stringify({
                downloads_used: newUsedCount,
                last_used_at: new Date().toISOString(),
              }),
            }),
            sbFetch(env, 'trezzy_downloads', {
              method: 'POST',
              body: JSON.stringify({
                token_code: token,
                arquivo: onlyFilename,
                topico: body.topico || 'Geral',
              }),
            }),
          ]);
        }

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

        return jsonResponse({
          url: signedRequest.url,
          expires_in: 300,
          quota: memberRecord
            ? {
                planName: memberRecord.plan_name,
                used: newUsedCount,
                max: memberRecord.max_downloads,
              }
            : null,
        });
      } catch (err) {
        console.error('[R2_WORKER_ERROR]', err);
        return jsonResponse({ error: 'Erro interno ao gerar download.' }, 500);
      }
    }

    return env.ASSETS.fetch(request);
  },
};

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      ...corsHeaders,
    },
  });
}
