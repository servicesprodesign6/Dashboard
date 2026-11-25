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

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    // 1. Proxy interno para o catalogo_site.json (inclui prefixo stl/index/)
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
        };

        if (!body.arquivo || typeof body.arquivo !== 'string') {
          return jsonResponse({ error: 'Nome do arquivo inválido.' }, 400);
        }

        const safeFilename = body.arquivo
          .replace(/^(\.\.(\/|\\|$))+/, '')
          .replace(/^\/+/, '');

        // Mantém o prefixo caso já venha no JSON, ou adiciona stl/arquivos/
        let objectKey = safeFilename;
        if (!safeFilename.startsWith('stl/') && !safeFilename.startsWith('arquivos/')) {
          objectKey = `stl/arquivos/${safeFilename}`;
        }

        const downloadFilename =
          safeFilename.split('/').pop() || 'modelo-trezzy.3mf';

        const r2 = new AwsClient({
          accessKeyId: env.R2_ACCESS_KEY_ID,
          secretAccessKey: env.R2_SECRET_ACCESS_KEY,
          service: 's3',
          region: 'auto',
        });

        const endpoint = new URL(
          `https://${env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com/${env.R2_PRIVATE_BUCKET_NAME}/${objectKey}`
        );
        endpoint.searchParams.set('X-Amz-Expires', '300');
        endpoint.searchParams.set(
          'response-content-disposition',
          `attachment; filename="${encodeURIComponent(downloadFilename)}"`
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
