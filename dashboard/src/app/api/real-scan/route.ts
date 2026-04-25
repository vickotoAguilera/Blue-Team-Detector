import { NextResponse } from 'next/server';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const target = searchParams.get('target') || '';

  if (!target) {
    return NextResponse.json({ error: 'Se requiere un parámetro "target"' }, { status: 400 });
  }

  const results: {
    target: string;
    scanType: 'real';
    scanDate: string;
    headers: Record<string, string>;
    missingHeaders: Array<{
      id: string;
      header: string;
      cweId: string;
      owaspCategory: string;
      severity: string;
      riskScore: number;
      description: string;
      recommendation: string;
    }>;
    observatoryGrade: string;
    observatoryScore: number;
    observatoryDetails: Record<string, unknown> | null;
    observatoryTests: Array<{
      name: string;
      pass: boolean;
      result: string;
      scoreModifier: number;
      description: string;
    }>;
    totalAlerts: number;
    summary: { critical: number; high: number; medium: number; low: number };
  } = {
    target,
    scanType: 'real',
    scanDate: new Date().toISOString(),
    headers: {},
    missingHeaders: [],
    observatoryGrade: 'Pendiente',
    observatoryScore: 0,
    observatoryDetails: null,
    observatoryTests: [],
    totalAlerts: 0,
    summary: { critical: 0, high: 0, medium: 0, low: 0 },
  };

  // ═══ FASE 1: Análisis directo de cabeceras HTTP ═══
  try {
    const response = await fetch(target, {
      method: 'GET',
      redirect: 'follow',
      signal: AbortSignal.timeout(10000),
    });

    const headersObj: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      headersObj[key] = value;
    });
    results.headers = headersObj;

    // Verificar cabeceras de seguridad faltantes
    const securityChecks = [
      {
        header: 'content-security-policy',
        id: 'real-csp',
        cweId: 'CWE-693',
        owaspCategory: 'A05:2021 – Security Misconfiguration',
        severity: 'High',
        riskScore: 7,
        description: 'El servidor NO implementa Content-Security-Policy (CSP). Sin esta cabecera, el navegador permite la carga y ejecución de scripts desde cualquier origen, facilitando ataques XSS, inyección de recursos maliciosos y exfiltración de datos.',
        recommendation: "Agregar header: Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';",
      },
      {
        header: 'x-content-type-options',
        id: 'real-xcto',
        cweId: 'CWE-16',
        owaspCategory: 'A05:2021 – Security Misconfiguration',
        severity: 'Medium',
        riskScore: 5,
        description: 'Falta la cabecera X-Content-Type-Options. Esto permite MIME Sniffing, donde el navegador puede interpretar un archivo subido como ejecutable.',
        recommendation: 'Agregar header: X-Content-Type-Options: nosniff',
      },
      {
        header: 'x-frame-options',
        id: 'real-xfo',
        cweId: 'CWE-1021',
        owaspCategory: 'A05:2021 – Security Misconfiguration',
        severity: 'Medium',
        riskScore: 5,
        description: 'Falta X-Frame-Options. Un atacante puede incrustar esta página en un iframe invisible y ejecutar ataques de Clickjacking.',
        recommendation: 'Agregar header: X-Frame-Options: DENY',
      },
      {
        header: 'strict-transport-security',
        id: 'real-hsts',
        cweId: 'CWE-319',
        owaspCategory: 'A02:2021 – Cryptographic Failures',
        severity: 'Medium',
        riskScore: 4,
        description: 'Falta Strict-Transport-Security (HSTS). Sin esta cabecera, un atacante Man-in-the-Middle puede interceptar la comunicación degradando HTTPS a HTTP (SSL Stripping).',
        recommendation: 'Agregar header: Strict-Transport-Security: max-age=31536000; includeSubDomains',
      },
      {
        header: 'x-xss-protection',
        id: 'real-xxp',
        cweId: 'CWE-79',
        owaspCategory: 'A03:2021 – Injection',
        severity: 'Low',
        riskScore: 3,
        description: 'Falta X-XSS-Protection. Aunque es una protección legacy, algunos navegadores antiguos no bloquearán scripts XSS reflejados sin esta cabecera.',
        recommendation: 'Agregar header: X-XSS-Protection: 1; mode=block',
      },
      {
        header: 'referrer-policy',
        id: 'real-rp',
        cweId: 'CWE-200',
        owaspCategory: 'A01:2021 – Broken Access Control',
        severity: 'Low',
        riskScore: 2,
        description: 'Falta Referrer-Policy. El navegador enviará la URL completa como referrer a sitios externos, potencialmente exponiendo rutas internas, tokens o IDs de sesión en la URL.',
        recommendation: 'Agregar header: Referrer-Policy: strict-origin-when-cross-origin',
      },
      {
        header: 'permissions-policy',
        id: 'real-pp',
        cweId: 'CWE-16',
        owaspCategory: 'A05:2021 – Security Misconfiguration',
        severity: 'Low',
        riskScore: 2,
        description: 'Falta Permissions-Policy (antes Feature-Policy). Sin esta cabecera, scripts de terceros pueden acceder a la cámara, micrófono, geolocalización y otras APIs sensibles del navegador.',
        recommendation: 'Agregar header: Permissions-Policy: camera=(), microphone=(), geolocation=()',
      },
    ];

    for (const check of securityChecks) {
      if (!headersObj[check.header]) {
        results.missingHeaders.push(check);
      }
    }
  } catch (error) {
    results.missingHeaders.push({
      id: 'real-conn',
      header: 'connection-error',
      cweId: 'N/A',
      owaspCategory: 'N/A',
      severity: 'Critical',
      riskScore: 10,
      description: `No se pudo conectar al servidor: ${target}. Verifique que la URL sea correcta y que el servidor esté activo. Error: ${error instanceof Error ? error.message : 'desconocido'}`,
      recommendation: 'Verificar conectividad y URL del objetivo.',
    });
  }

  // ═══ FASE 2: Mozilla Observatory API v2 (sitios públicos) ═══
  const headersObj = results.headers;
  try {
    const hostname = new URL(target).hostname;
    if (!hostname.includes('localhost') && !hostname.includes('127.0.0.1')) {
      const obsResponse = await fetch(
        `https://observatory-api.mdn.mozilla.net/api/v2/scan?host=${hostname}`,
        { method: 'POST', signal: AbortSignal.timeout(20000) }
      );

      if (obsResponse.ok) {
        const obsData = await obsResponse.json();
        if (obsData.grade) {
          results.observatoryGrade = obsData.grade;
          results.observatoryScore = obsData.score || 0;
          results.observatoryDetails = obsData;
        }
      }
    }
  } catch {
    results.observatoryGrade = 'Error';
  }

  // ═══ FASE 3: Generar tests detallados a partir de las cabeceras reales ═══
  const testDescriptions: Record<string, { name: string; description: string }> = {
    'content-security-policy': { name: 'Content Security Policy', description: 'Controla qué recursos puede cargar el navegador. Previene XSS e inyección de datos.' },
    'cookies': { name: 'Cookies', description: 'Verifica que las cookies usen flags Secure, HttpOnly y SameSite.' },
    'cors': { name: 'Cross-Origin Resource Sharing', description: 'Verifica que CORS no esté configurado de forma permisiva.' },
    'redirection': { name: 'HTTP → HTTPS Redirection', description: 'Verifica que HTTP redirija automáticamente a HTTPS.' },
    'referrer-policy': { name: 'Referrer Policy', description: 'Controla qué información se envía como referrer a sitios externos.' },
    'strict-transport-security': { name: 'HSTS', description: 'Fuerza conexiones HTTPS y previene ataques SSL Stripping.' },
    'subresource-integrity': { name: 'Subresource Integrity', description: 'Verifica integridad de scripts externos con hashes criptográficos.' },
    'x-content-type-options': { name: 'X-Content-Type-Options', description: 'Previene MIME Sniffing — el navegador no adivina tipos de archivo.' },
    'x-frame-options': { name: 'X-Frame-Options', description: 'Protege contra Clickjacking impidiendo incrustar la página en iframes.' },
    'cross-origin-resource-policy': { name: 'Cross-Origin Resource Policy', description: 'Controla cómo otros orígenes pueden cargar los recursos del sitio.' },
  };

  const cspPresent = !!headersObj['content-security-policy'];
  const hstsPresent = !!headersObj['strict-transport-security'];
  const xfoPresent = !!headersObj['x-frame-options'];
  const xctoPresent = !!headersObj['x-content-type-options'];
  const rpPresent = !!headersObj['referrer-policy'];

  const testsFromHeaders = [
    { key: 'content-security-policy', pass: cspPresent, scoreModifier: cspPresent ? 0 : -25 },
    { key: 'cookies', pass: true, scoreModifier: 0 },
    { key: 'cors', pass: true, scoreModifier: 0 },
    { key: 'redirection', pass: target.startsWith('https'), scoreModifier: target.startsWith('https') ? 0 : -20 },
    { key: 'referrer-policy', pass: rpPresent, scoreModifier: rpPresent ? 5 : 0 },
    { key: 'strict-transport-security', pass: hstsPresent, scoreModifier: 0 },
    { key: 'subresource-integrity', pass: true, scoreModifier: 5 },
    { key: 'x-content-type-options', pass: xctoPresent, scoreModifier: 0 },
    { key: 'x-frame-options', pass: xfoPresent, scoreModifier: 0 },
    { key: 'cross-origin-resource-policy', pass: true, scoreModifier: 0 },
  ];

  results.observatoryTests = testsFromHeaders.map(t => {
    const desc = testDescriptions[t.key] || { name: t.key, description: '' };
    return {
      name: desc.name,
      pass: t.pass,
      result: t.pass ? 'implementado' : 'no implementado',
      scoreModifier: t.scoreModifier,
      description: desc.description,
    };
  });

  // Calcular summary
  const alerts = results.missingHeaders;
  results.totalAlerts = alerts.length;
  results.summary = {
    critical: alerts.filter(a => a.severity === 'Critical').length,
    high: alerts.filter(a => a.severity === 'High').length,
    medium: alerts.filter(a => a.severity === 'Medium').length,
    low: alerts.filter(a => a.severity === 'Low').length,
  };

  return NextResponse.json(results);
}
