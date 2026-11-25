import { AwsClient } from 'aws4fetch';

export interface Env {
  ASSETS: {
    fetch: (request: Request) => Promise<Response>;
  };
  TREZZY_KV?: KVNamespace;
  R2_ACCOUNT_ID: string;
  R2_ACCESS_KEY_ID: string;
  R2_SECRET_ACCESS_KEY: string;
  R2_PRIVATE_BUCKET_NAME: string;
  MEMBER_ACCESS_SECRET: string;
  R2_PUBLIC_URL: string;
}

type PlanTier = 'teste' | 'premium' | 'vip';

interface TokenRecord {
  code: string;
  label: string;
  plan: PlanTier;
  planName: string;
  maxDownloads: number | null; // null = ilimitado (VIP)
  downloadsUsed: number;
  createdAt: string;
  lastUsedAt?: string;
  lastFile?: string;
}

const PLAN_CONFIG: Record<PlanTier, { name: string; max: number | null }> = {
  teste: { name: 'Teste (10 Downloads)', max: 10 },
  premium: { name: 'Premium (50 Downloads)', max: 50 },
  vip: { name: 'VIP (Ilimitado + Updates)', max: null },
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
          const res = await fetch(targetUrl, {
            cf: { cacheTtl: 60, cacheEverything: true },
          });
          if (res.ok) {
            const text = await res.text();
            return new Response(text, {
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
      return jsonResponse({ error: 'catalogo_site.json não encontrado no bucket R2.' }, 404);
    }

    // 2. Login / Verificação de Plano
    if (url.pathname === '/api/auth/login' && request.method === 'POST') {
      const body = (await request.json()) as { password?: string };
      const inputPass = (body.password || '').trim();
      const adminPass = await getAdminPassword(env);

      if (inputPass && inputPass === adminPass) {
        return jsonResponse({
          role: 'admin',
          token: inputPass,
          message: 'Acesso administrativo liberado.',
        });
      }

      if (env.TREZZY_KV && inputPass) {
        const rawToken = await env.TREZZY_KV.get(`TOKEN:${inputPass}`);
        if (rawToken) {
          const record = JSON.parse(rawToken) as TokenRecord;
          const esgotado =
            record.maxDownloads !== null && record.downloadsUsed >= record.maxDownloads;

          if (esgotado) {
            return jsonResponse(
              { error: `Limite de ${record.maxDownloads} downloads atingido neste token.` },
              403
            );
          }

          return jsonResponse({
            role: 'member',
            token: inputPass,
            plan: record.plan,
            planName: record.planName,
            maxDownloads: record.maxDownloads,
            downloadsUsed: record.downloadsUsed,
            label: record.label,
          });
        }
      }

      return jsonResponse({ error: 'Senha ou Token inválido.' }, 401);
    }

    // 3. Alterar Senha Administrativa
    if (url.pathname === '/api/auth/change-password' && request.method === 'POST') {
      if (!env.TREZZY_KV) {
        return jsonResponse({ error: 'Associe TREZZY_KV nas Configurações do Worker primeiro.' }, 500);
      }

      const authHeader = request.headers.get('Authorization') || '';
      const currentToken = authHeader.replace(/^Bearer\s+/i, '').trim();
      const adminPass = await getAdminPassword(env);

      if (currentToken !== adminPass) {
        return jsonResponse({ error: 'Apenas o administrador pode alterar a senha.' }, 403);
      }

      const body = (await request.json()) as { newPassword?: string };
      const newPass = (body.newPassword || '').trim();

      if (newPass.length < 4) {
        return jsonResponse({ error: 'A nova senha deve ter pelo menos 4 caracteres.' }, 400);
      }

      await env.TREZZY_KV.put('ADMIN_CUSTOM_PASSWORD', newPass);
      return jsonResponse({ success: true, token: newPass });
    }

    // 4. Gerenciar Tokens por Plano (Listar / Criar / Revogar)
    if (url.pathname === '/api/tokens') {
      if (!env.TREZZY_KV) {
        return jsonResponse({ error: 'Binding TREZZY_KV não configurado no Worker.' }, 500);
      }

      const authHeader = request.headers.get('Authorization') || '';
      const token = authHeader.replace(/^Bearer\s+/i, '').trim();
      const adminPass = await getAdminPassword(env);

      if (token !== adminPass) {
        return jsonResponse({ error: 'Acesso restrito ao administrador.' }, 403);
      }

      if (request.method === 'GET') {
        const list = await env.TREZZY_KV.list({ prefix: 'TOKEN:' });
        const tokens: TokenRecord[] = [];
        for (const key of list.keys) {
          const val = await env.TREZZY_KV.get(key.name);
          if (val) tokens.push(JSON.parse(val));
        }
        tokens.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
        return jsonResponse({ tokens });
      }

      if (request.method === 'POST') {
        const body = (await request.json()) as { label?: string; plan?: PlanTier };
        const planKey: PlanTier =
          body.plan && PLAN_CONFIG[body.plan] ? body.plan : 'teste';
        const cfg = PLAN_CONFIG[planKey];

        const prefixMap: Record<PlanTier, string> = {
          teste: 'TRZ-TEST',
          premium: 'TRZ-PRO',
          vip: 'TRZ-VIP',
        };
        const randomPart = crypto.randomUUID().split('-')[0].toUpperCase();
        const code = `${prefixMap[planKey]}-${randomPart}`;

        const record: TokenRecord = {
          code,
          label: (body.label || 'Cliente').trim(),
          plan: planKey,
          planName: cfg.name,
          maxDownloads: cfg.max,
          downloadsUsed: 0,
          createdAt: new Date().toISOString(),
        };

        await env.TREZZY_KV.put(`TOKEN:${code}`, JSON.stringify(record));
        return jsonResponse({ token: record });
      }

      if (request.method === 'DELETE') {
        const code = url.searchParams.get('code');
        if (code) {
          await env.TREZZY_KV.delete(`TOKEN:${code}`);
        }
        return jsonResponse({ success: true });
      }
    }

    // 5. Endpoint de Download Protegido com Contagem de Cota por Plano
    if (url.pathname === '/api/download' && request.method === 'POST') {
      try {
        const authHeader = request.headers.get('Authorization') || '';
        const token = authHeader.replace(/^Bearer\s+/i, '').trim();

        if (!token) {
          return jsonResponse({ error: 'Faça login ou insira um token válido.' }, 401);
        }

        const adminPass = await getAdminPassword(env);
        const isAdmin = token === adminPass;
        let memberRecord: TokenRecord | null = null;

        if (!isAdmin) {
          if (!env.TREZZY_KV) {
            return jsonResponse({ error: 'Chave de acesso inválida.' }, 403);
          }
          const raw = await env.TREZZY_KV.get(`TOKEN:${token}`);
          if (!raw) {
            return jsonResponse({ error: 'Token inválido ou revogado.' }, 403);
          }
          memberRecord = JSON.parse(raw) as TokenRecord;

          if (
            memberRecord.maxDownloads !== null &&
            memberRecord.downloadsUsed >= memberRecord.maxDownloads
          ) {
            return jsonResponse(
              {
                error: `Cota esgotada! Você já usou todos os ${memberRecord.maxDownloads} downloads do plano ${memberRecord.planName}.`,
              },
              403
            );
          }
        }

        const body = (await request.json()) as {
          chave?: string;
          arquivo?: string;
          caminho_relativo?: string;
          topico?: string;
        };

        const rawPath = body.caminho_relativo || body.arquivo;
        if (!rawPath || typeof rawPath !== 'string') {
          return jsonResponse({ error: 'Nome do arquivo inválido.' }, 400);
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

          const headUrl = `${baseBucketUrl}/${encodedKey}`;
          const signedHead = await r2.sign(new Request(headUrl, { method: 'HEAD' }));
          const checkRes = await fetch(signedHead);

          if (checkRes.ok) {
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
          return jsonResponse(
            { error: `Arquivo "${onlyFilename}" não encontrado no servidor Trezzy 3D.` },
            404
          );
        }

        // Desconta 1 download da cota do cliente (ou apenas registra o último arquivo se for VIP)
        if (memberRecord && env.TREZZY_KV) {
          memberRecord.downloadsUsed += 1;
          memberRecord.lastUsedAt = new Date().toISOString();
          memberRecord.lastFile = onlyFilename;
          await env.TREZZY_KV.put(`TOKEN:${token}`, JSON.stringify(memberRecord));
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
                planName: memberRecord.planName,
                used: memberRecord.downloadsUsed,
                max: memberRecord.maxDownloads,
              }
            : null,
        });
      } catch (err) {
        console.error('[R2_WORKER_ERROR]', err);
        return jsonResponse({ error: 'Falha ao gerar link seguro no R2.' }, 500);
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
