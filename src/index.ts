import { AwsClient } from 'aws4fetch';

export interface Env {
  ASSETS: {
    fetch: (request: Request) => Promise<Response>;
  };
  R2_ACCOUNT_ID: string;
  R2_ACCESS_KEY_ID: string;
  R2_SECRET_ACCESS_KEY: string;
  R2_PRIVATE_BUCKET_NAME: string;
  MEMBER_ACCESS_SECRET: string;
  R2_PUBLIC_URL: string;
}

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
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

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    // 1. Proxy interno para o catalogo_site.json
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
          // tenta próximo caminho
        }
      }

      return jsonResponse(
        { error: 'catalogo_site.json não encontrado no bucket R2.' },
        404
      );
    }

    // 2. Endpoint Protegido de Download (/api/download)
    if (url.pathname === '/api/download' && request.method === 'POST') {
      try {
        const authHeader = request.headers.get('Authorization') || '';
        const token = authHeader.replace(/^Bearer\s+/i, '').trim();

        if (!token) {
          return jsonResponse(
            { error: 'Acesso negado. Informe sua chave de membro.' },
            401
          );
        }

        if (env.MEMBER_ACCESS_SECRET && token !== env.MEMBER_ACCESS_SECRET) {
          return jsonResponse(
            { error: 'Chave de acesso inválida ou expirada.' },
            403
          );
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

        const safeFilename = rawPath
          .replace(/^(\.\.(\/|\\|$))+/, '')
          .replace(/^\/+/, '');

        const onlyFilename = safeFilename.split('/').pop() || safeFilename;
        const topicoSlug = body.topico ? slugifyTopico(body.topico) : '';

        const r2 = new AwsClient({
          accessKeyId: env.R2_ACCESS_KEY_ID,
          secretAccessKey: env.R2_SECRET_ACCESS_KEY,
          service: 's3',
          region: 'auto',
        });

        const baseBucketUrl = `https://${env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com/${env.R2_PRIVATE_BUCKET_NAME}`;

        // Candidatos diretos baseados na estrutura real do bucket (arquivos/<slug>/<arquivo>)
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
          const signedHead = await r2.sign(
            new Request(headUrl, { method: 'HEAD' })
          );
          const checkRes = await fetch(signedHead);

          if (checkRes.ok) {
            keyEncontrada = encodedKey;
            break;
          }
        }

        // Plano B infalível: busca o objeto no bucket pelo prefixo de ID/nome se a subpasta tiver outro nome
        if (!keyEncontrada) {
          const listUrl = new URL(baseBucketUrl);
          listUrl.searchParams.set('list-type', '2');
          listUrl.searchParams.set('max-keys', '1000');

          const signedList = await r2.sign(
            new Request(listUrl.toString(), { method: 'GET' })
          );
          const listRes = await fetch(signedList);

          if (listRes.ok) {
            const xml = await listRes.text();
            const keyMatches = [...xml.matchAll(/<Key>(.*?)<\/Key>/g)].map(
              (m) => m[1]
            );
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
            {
              error: `Arquivo "${onlyFilename}" não encontrado no servidor Trezzy 3D.`,
            },
            404
          );
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
          chave: body.chave || null,
        });
      } catch (err) {
        console.error('[R2_WORKER_ERROR]', err);
        return jsonResponse(
          { error: 'Falha ao gerar link seguro no R2.' },
          500
        );
      }
    }

    // 3. Entrega o Front-End
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
