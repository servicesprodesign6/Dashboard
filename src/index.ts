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

interface TokenRecord {
  code: string;
  label: string;
  createdAt: string;
  used: boolean;
  usedAt?: string;
  usedFile?: string;
}

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

    // 2. Login / Verificação de Sessão
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

      // Verifica se é um token de uso único válido
      if (env.TREZZY_KV && inputPass) {
        const rawToken = await env.TREZZY_KV.get(`TOKEN:${inputPass}`);
        if (rawToken) {
          const record = JSON.parse(rawToken) as TokenRecord;
          if (!record.used) {
            return jsonResponse({
              role: 'guest_single_use',
              token: inputPass,
              label: record.label,
              message: 'Token de uso único validado (1 download disponível).',
            });
          } else {
            return jsonResponse({ error: 'Este token de uso único já foi utilizado.' }, 403);
          }
        }
      }

      return jsonResponse({ error: 'Senha ou Token inválido.' }, 401);
    }

    // 3. Alterar Senha Administrativa
    if (url.pathname === '/api/auth/change-password' && request.method === 'POST') {
      if (!env.TREZZY_KV) {
        return jsonResponse({ error: 'Configure o binding TREZZY_KV no painel Cloudflare primeiro.' }, 500);
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

    // 4. Gerenciar Tokens de Uso Único (Listar / Criar / Revogar)
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

      // Listar todos os tokens
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

      // Criar novo token de uso único
      if (request.method === 'POST') {
        const body = (await request.json()) as { label?: string };
        const randomPart = crypto.randomUUID().split('-')[0].toUpperCase();
        const code = `TRZ-${randomPart}`;

        const record: TokenRecord = {
          code,
          label: (body.label || 'Cliente Avulso').trim(),
          createdAt: new Date().toISOString(),
          used: false,
        };

        await env.TREZZY_KV.put(`TOKEN:${code}`, JSON.stringify(record));
        return jsonResponse({ token: record });
      }

      // Excluir token
      if (request.method === 'DELETE') {
        const code = url.searchParams.get('code');
        if (code) {
          await env.TREZZY_KV.delete(`TOKEN:${code}`);
        }
        return jsonResponse({ success: true });
      }
    }

    // 5. Endpoint de Download Protegido (Suporta Admin + Token de Uso Único)
    if (url.pathname === '/api/download' && request.method === 'POST') {
      try {
        const authHeader = request.headers.get('Authorization') || '';
        const token = authHeader.replace(/^Bearer\s+/i, '').trim();

        if (!token) {
          return jsonResponse({ error: 'Faça login ou insira um token válido.' }, 401);
        }

        const adminPass = await getAdminPassword(env);
        const isAdmin = token === adminPass;
        let singleUseRecord: TokenRecord | null = null;

        if (!isAdmin) {
          if (!env.TREZZY_KV) {
            return jsonResponse({ error: 'Chave de acesso inválida.' }, 403);
          }
          const raw = await env.TREZZY_KV.get(`TOKEN:${token}`);
          if (!raw) {
            return jsonResponse({ error: 'Token inválido ou inexistente.' }, 403);
          }
          singleUseRecord = JSON.parse(raw) as TokenRecord;
          if (singleUseRecord.used) {
            return jsonResponse({ error: 'Este token já foi utilizado e expirou.' }, 403);
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

        // Queima o token de uso único imediatamente após encontrar o arquivo!
        if (singleUseRecord && env.TREZZY_KV) {
          singleUseRecord.used = true;
          singleUseRecord.usedAt = new Date().toISOString();
          singleUseRecord.usedFile = onlyFilename;
          await env.TREZZY_KV.put(`TOKEN:${token}`, JSON.stringify(singleUseRecord));
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
          single_use_consumed: Boolean(singleUseRecord),
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
