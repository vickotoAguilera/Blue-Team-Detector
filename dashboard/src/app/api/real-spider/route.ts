import { NextResponse } from 'next/server';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const target = searchParams.get('target') || '';

  if (!target) {
    return NextResponse.json({ error: 'Se requiere parámetro "target"' }, { status: 400 });
  }

  const results: {
    target: string;
    endpoints: Array<{
      url: string;
      method: string;
      type: string;
      context: string;
    }>;
    forms: Array<{
      action: string;
      method: string;
      inputs: string[];
    }>;
    scripts: string[];
    totalDiscovered: number;
  } = {
    target,
    endpoints: [],
    forms: [],
    scripts: [],
    totalDiscovered: 0,
  };

  try {
    const response = await fetch(target, {
      method: 'GET',
      redirect: 'follow',
      signal: AbortSignal.timeout(15000),
      headers: {
        'User-Agent': 'BlueTeam-Spider/1.0 (Vulnerability Assessment)',
      },
    });

    const html = await response.text();
    const baseUrl = new URL(target);

    // ═══ Extraer enlaces <a href="..."> ═══
    const linkRegex = /<a[^>]+href=["']([^"'#]+)["'][^>]*>/gi;
    let match;
    const seenUrls = new Set<string>();

    while ((match = linkRegex.exec(html)) !== null) {
      let href = match[1].trim();
      if (!href || href.startsWith('javascript:') || href.startsWith('mailto:') || href.startsWith('tel:')) continue;

      // Resolver URLs relativas
      try {
        const resolvedUrl = new URL(href, baseUrl.origin);
        href = resolvedUrl.href;
      } catch {
        continue;
      }

      if (!seenUrls.has(href)) {
        seenUrls.add(href);
        const isInternal = href.includes(baseUrl.hostname);
        results.endpoints.push({
          url: href,
          method: 'GET',
          type: isInternal ? 'internal' : 'external',
          context: 'Enlace <a>',
        });
      }
    }

    // ═══ Extraer formularios <form> ═══
    const formRegex = /<form[^>]*action=["']([^"']*)["'][^>]*method=["']([^"']*)["'][^>]*>([\s\S]*?)<\/form>/gi;
    while ((match = formRegex.exec(html)) !== null) {
      const action = match[1] || '/';
      const method = (match[2] || 'GET').toUpperCase();
      const formBody = match[3];

      // Extraer inputs del formulario
      const inputRegex = /<input[^>]+name=["']([^"']+)["'][^>]*/gi;
      const inputs: string[] = [];
      let inputMatch;
      while ((inputMatch = inputRegex.exec(formBody)) !== null) {
        inputs.push(inputMatch[1]);
      }

      let resolvedAction = action;
      try {
        resolvedAction = new URL(action, baseUrl.origin).href;
      } catch { /* keep as-is */ }

      results.forms.push({ action: resolvedAction, method, inputs });

      if (!seenUrls.has(resolvedAction)) {
        seenUrls.add(resolvedAction);
        results.endpoints.push({
          url: resolvedAction,
          method,
          type: 'form-action',
          context: `Formulario con inputs: ${inputs.join(', ') || 'ninguno'}`,
        });
      }
    }

    // ═══ Extraer scripts <script src="..."> ═══
    const scriptRegex = /<script[^>]+src=["']([^"']+)["'][^>]*>/gi;
    while ((match = scriptRegex.exec(html)) !== null) {
      let src = match[1].trim();
      try {
        src = new URL(src, baseUrl.origin).href;
      } catch { /* keep */ }
      results.scripts.push(src);

      if (!seenUrls.has(src)) {
        seenUrls.add(src);
        results.endpoints.push({
          url: src,
          method: 'GET',
          type: 'script',
          context: 'Script externo <script src>',
        });
      }
    }

    // ═══ Extraer imágenes <img src="..."> ═══
    const imgRegex = /<img[^>]+src=["']([^"']+)["'][^>]*>/gi;
    while ((match = imgRegex.exec(html)) !== null) {
      let src = match[1].trim();
      if (src.startsWith('data:')) continue;
      try {
        src = new URL(src, baseUrl.origin).href;
      } catch { continue; }

      if (!seenUrls.has(src)) {
        seenUrls.add(src);
        results.endpoints.push({
          url: src,
          method: 'GET',
          type: 'asset',
          context: 'Imagen <img>',
        });
      }
    }

    // ═══ Extraer APIs/Fetch calls ═══
    const fetchRegex = /fetch\s*\(\s*['"`]([^'"`]+)['"`]/gi;
    while ((match = fetchRegex.exec(html)) !== null) {
      let apiUrl = match[1].trim();
      try {
        apiUrl = new URL(apiUrl, baseUrl.origin).href;
      } catch { /* keep */ }

      if (!seenUrls.has(apiUrl)) {
        seenUrls.add(apiUrl);
        results.endpoints.push({
          url: apiUrl,
          method: 'GET/POST',
          type: 'api',
          context: 'Llamada fetch() en JavaScript',
        });
      }
    }

    results.totalDiscovered = results.endpoints.length;

  } catch (error) {
    return NextResponse.json({
      error: `No se pudo conectar: ${error instanceof Error ? error.message : 'desconocido'}`,
      target,
    }, { status: 500 });
  }

  return NextResponse.json(results);
}
