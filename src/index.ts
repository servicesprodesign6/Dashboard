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

    // 1. Pré-voo CORS
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    // 2. Endpoint Protegido de Download (/api/download)
    if (url.pathname === '/api/download' && request.method === 'POST') {
      try {
        // Verifica Token de Acesso do Membro
        const authHeader = request.headers.get('Authorization') || '';
        const token = authHeader.replace(/^Bearer\s+/i, '').trim();

        if (!token) {
          return jsonResponse(
            { error: 'Acesso negado. Informe sua chave/token de membro.' },
            401
          );
        }

        if (env.MEMBER_ACCESS_SECRET && token !== env.MEMBER_ACCESS_SECRET) {
          return jsonResponse(
            { error: 'Token inválido ou assinatura expirada.' },
            403
          );
        }

        // Lê dados do arquivo solicitado
        const body = (await request.json()) as {
          chave?: string;
          arquivo?: string;
        };

        if (!body.arquivo || typeof body.arquivo !== 'string') {
          return jsonResponse({ error: 'Nome do arquivo inválido.' }, 400);
        }

        // Sanitização contra Path Traversal
        const safeFilename = body.arquivo
          .replace(/^(\.\.(\/|\\|$))+/, '')
          .replace(/^\/+/, '');

        // Garante prefixo da pasta no bucket privado (ajuste se os arquivos estiverem na raiz)
        const objectKey = safeFilename.startsWith('arquivos/')
          ? safeFilename
          : `arquivos/${safeFilename}`;

        const downloadFilename =
          safeFilename.split('/').pop() || 'modelo-trezzy.3mf';

        // Inicializa cliente S3 compatível com Cloudflare Workers
        const r2 = new AwsClient({
          accessKeyId: env.R2_ACCESS_KEY_ID,
          secretAccessKey: env.R2_SECRET_ACCESS_KEY,
          service: 's3',
          region: 'auto',
        });

        // Monta URL do objeto no bucket privado com expiração de 300s (5 minutos)
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

    // 3. Entrega o Front-End (public/index.html) para todas as outras rotas
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
