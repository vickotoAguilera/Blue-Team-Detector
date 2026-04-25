import { NextResponse } from 'next/server';
import Groq from 'groq-sdk';

const groq = new Groq({
  apiKey: process.env.GROQ_API_KEY,
});

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { cweId, name, description, owaspCategory, affectedUrl, nvdData } = body;

    if (!cweId || !name) {
      return NextResponse.json({ error: 'Missing alert details' }, { status: 400 });
    }

    // ═══ SISTEMA DE SANITIZACIÓN (Blue Team Compliance) ═══
    const sanitizedUrl = affectedUrl
      ? affectedUrl.replace(/localhost:\d+/g, '[SERVIDOR_OBJETIVO]').replace(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/g, '[IP_REDACTADA]')
      : 'No disponible';

    let nvdContext = '';
    if (nvdData) {
      nvdContext = `
--- INFORMACIÓN OFICIAL DE NVD (National Vulnerability Database) ---
- CVE ID: ${nvdData.cveId}
- Descripción Oficial: ${nvdData.description}
- Severidad Base: ${nvdData.severity} (${nvdData.baseScore})
- Vector CVSS: ${nvdData.vectorString}
- Referencias Externas: ${nvdData.references?.slice(0, 3).join(', ')}
------------------------------------------------------------------
`;
    }

    const prompt = `Actúa como un arquitecto de seguridad web experimentado del Blue Team.
Se ha detectado la siguiente vulnerabilidad durante una auditoría preventiva:

- Código CWE: ${cweId}
- Nombre: ${name}
- Categoría OWASP Top 10: ${owaspCategory || 'No clasificada'}
- URL afectada (sanitizada): ${sanitizedUrl}
- Descripción técnica local: ${description}
${nvdContext}

Estructura tu respuesta en español usando formato Markdown con estas 4 secciones:

## 🔍 ¿Qué significa esta vulnerabilidad?
Explica en lenguaje claro y comprensible (para un analista junior que recién se integra al equipo de Ciberseguridad) qué es este fallo, por qué existe, y qué podría hacer un atacante si lo encuentra primero. Usa analogías simples y cita explícitamente la categoría de OWASP Top 10 (2025) correspondiente, incluyendo un enlace de referencia oficial de la documentación de OWASP (ej: https://owasp.org/Top10/...).

## ⚠️ Impacto en la Organización y "Compliance"
Detalla el impacto técnico y humano: qué datos quedan expuestos, cómo afecta la confianza de los usuarios, el estrés operativo del equipo de TI, y las consecuencias legales/reputacionales para la institución. Menciona cómo esto afecta la puntuación en auditorías internacionales.

## 🛡️ Código de Remediación (Parche Profesional de Seguridad)
Proporciona el fragmento de código EXACTO y listo para copiar-pegar que el analista debe aplicar para cerrar esta vulnerabilidad. Incluye soluciones para:
- **Next.js / Node.js** (utilizando mejores prácticas de sanitización y parametrización).
- **Hardening de Infraestructura** (Nginx, WAF o configuraciones cloud según aplique).
Cada bloque de código debe estar en un bloque de código con el lenguaje especificado. Asegúrate de que el código sea moderno y siga los estándares de seguridad actuales.

## 📋 Verificación y Evidencia Post-Parche
Indica los pasos exactos para verificar que el parche fue aplicado correctamente. Menciona qué herramientas se deben usar para re-escanear y confirmar la mitigación total.

No saludes ni introduzcas. Ve directo al contenido técnico con formato corporativo impecable.`;

    const completion = await groq.chat.completions.create({
      messages: [
        {
          role: 'system',
          content: 'Eres un arquitecto senior de ciberseguridad del Blue Team. Respondes exclusivamente en español formal. Tu prioridad es proteger la organización alineándote SIEMPRE con los estándares más recientes de OWASP Top 10 (2025 o superior) y CWE. Cada respuesta debe ser accionable, estar basada en las últimas normativas de seguridad, e incluir código real de remediación moderno.'
        },
        { role: 'user', content: prompt }
      ],
      model: 'llama-3.3-70b-versatile',
      temperature: 0.3,
      max_tokens: 2048,
    });

    const aiResponse = completion.choices[0]?.message?.content || 'No se recibió respuesta de la IA.';

    return NextResponse.json({ translation: aiResponse });

  } catch (error) {
    console.error('Error in Groq Translation API:', error);
    return NextResponse.json({ error: 'Failed to translate vulnerability' }, { status: 500 });
  }
}
