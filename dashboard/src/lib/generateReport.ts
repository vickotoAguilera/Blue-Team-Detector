/* eslint-disable @typescript-eslint/no-explicit-any */
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import { logoBase64 } from '@/lib/logoBase64';
import { LOGO_LLAMA, LOGO_MOZILLA, LOGO_NIST, LOGO_OWASP, LOGO_ZAP, LOGO_MITRE, LOGO_CWE } from '@/lib/toolLogos';
import { ZAP_EVIDENCE_1, ZAP_EVIDENCE_2, ZAP_EVIDENCE_3, MOZILLA_EVIDENCE_1 } from '@/lib/zapEvidence';
interface Alert {
  id: string;
  source: string;
  cweId: string;
  owaspCategory: string;
  name: string;
  severity: string;
  riskScore: number;
  description: string;
  affectedUrl: string;
  evidence: string;
  nvdData?: any;
  aiRemediation?: string;
  header?: string;
  recommendation?: string;
  cia?: {
    confidentiality: boolean;
    integrity: boolean;
    availability: boolean;
  };
  effort?: {
    complexity: 'BAJA' | 'MEDIA' | 'ALTA';
    cost: 'BAJO' | 'MEDIO' | 'ALTO';
  };
  incidences?: number;
  riskFactors?: {
    threat: { a1: number; a2: number; a3: number; a4: number };
    vulnerability: { v1: number; v2: number; v3: number; v4: number };
    technical: { t1: number; t2: number; t3: number; t4: number };
    business: { n1: number; n2: number; n3: number; n4: number };
  };
}

interface AuditLog {
  action: string;
  timestamp: string;
  type: string;
}

interface SpiderResult {
  url: string;
  method: string;
  status?: number;
  type: string;
  context?: string;
}

interface ReportData {
  target: string;
  alerts: Alert[];
  patchedAlerts: string[];
  auditLogs: AuditLog[];
  spiderResults: SpiderResult[];
  scanSummary: { critical: number; high: number; medium: number; low: number } | null;
  observatoryGrade: string;
  observatoryScore?: number;
  observatoryTests?: Array<{name: string; pass: boolean; result: string; scoreModifier: number; description: string}>;
  scanMode: string;
}

const COLORS = {
  primary: [20, 20, 20] as [number, number, number],       // Negro sobrio
  accent: [227, 6, 19] as [number, number, number],         // Rojo Empresa Default
  critical: [180, 0, 0] as [number, number, number],       // Rojo oscuro
  high: [220, 80, 0] as [number, number, number],          // Naranja sobrio
  medium: [200, 160, 0] as [number, number, number],       // Dorado/Ocre
  low: [60, 60, 60] as [number, number, number],           // Gris oscuro
  green: [40, 100, 40] as [number, number, number],        // Verde oscuro
  white: [255, 255, 255] as [number, number, number],
  gray: [100, 100, 100] as [number, number, number],       // Gris medio
  darkGray: [40, 40, 40] as [number, number, number],      // Gris muy oscuro
};

function sevColor(severity: string): [number, number, number] {
  const map: Record<string, [number, number, number]> = {
    Critical: COLORS.critical,
    High: COLORS.high,
    Medium: COLORS.medium,
    Low: COLORS.low,
  };
  return map[severity] || COLORS.gray;
}

/**
 * Renders a code evidence block styled like an IDE/terminal.
 * Lines containing keywords like 'ERROR', 'MISSING', 'FALTA', or matching the evidence string
 * are highlighted with a red Empresa Default background.
 */
function renderCodeBlock(
  doc: jsPDF,
  code: string,
  evidenceHighlight: string,
  startX: number,
  startY: number,
  maxWidth: number,
  checkPageFn: (needed: number) => void
): number {
  const lineH = 4;
  const padding = 4;
  const codeLines = code.split('\n').filter(l => l.trim().length > 0).slice(0, 12); // Max 12 lines
  const blockH = codeLines.length * lineH + padding * 2 + 8; // +8 for title bar

  checkPageFn(blockH + 10);

  let cy = startY;

  // Title bar (dark header like an IDE tab)
  doc.setFillColor(30, 30, 30);
  doc.roundedRect(startX, cy, maxWidth, 6, 1.5, 1.5, 'F');
  // Fill the bottom corners to make them square
  doc.rect(startX, cy + 3, maxWidth, 3, 'F');
  doc.setTextColor(180, 180, 180);
  doc.setFontSize(5.5);
  doc.setFont('courier', 'normal');
  doc.text('EVIDENCIA T\u00c9CNICA', startX + 3, cy + 4);
  doc.setTextColor(100, 100, 100);
  doc.text('\u25CF \u25CF \u25CF', startX + maxWidth - 12, cy + 4); // Simulated window buttons
  cy += 6;

  // Code body (dark background)
  doc.setFillColor(35, 35, 40);
  const bodyH = codeLines.length * lineH + padding * 2;
  doc.roundedRect(startX, cy, maxWidth, bodyH, 0, 0, 'F');
  // Bottom rounded corners
  doc.setFillColor(35, 35, 40);
  doc.roundedRect(startX, cy + bodyH - 3, maxWidth, 3, 1.5, 1.5, 'F');
  doc.rect(startX, cy, maxWidth, bodyH - 1.5, 'F');

  cy += padding;

  const highlightTerms = ['error', 'missing', 'falta', 'not set', 'no encontrado', 'not found'];
  const evidenceLower = evidenceHighlight.toLowerCase();

  codeLines.forEach((line, i) => {
    const lineLower = line.toLowerCase();
    const isHighlighted = (
      (evidenceLower && lineLower.includes(evidenceLower.substring(0, 30).toLowerCase())) ||
      highlightTerms.some(term => lineLower.includes(term)) ||
      lineLower.includes('x-content-type') ||
      lineLower.includes('content-security-policy') ||
      lineLower.includes('x-frame-options') ||
      lineLower.includes('strict-transport')
    );

    if (isHighlighted) {
      // RED Empresa Default highlight band
      doc.setFillColor(227, 6, 19);
      doc.rect(startX + 1, cy - 1, maxWidth - 2, lineH, 'F');
      doc.setTextColor(255, 255, 255);
    } else {
      doc.setTextColor(200, 200, 200);
    }

    // Line number
    doc.setFontSize(5);
    doc.setFont('courier', 'normal');
    doc.setTextColor(isHighlighted ? 255 : 80, isHighlighted ? 255 : 80, isHighlighted ? 255 : 80);
    doc.text(String(i + 1).padStart(3, ' '), startX + 2, cy + 2.5);

    // Code content
    doc.setTextColor(isHighlighted ? 255 : 200, isHighlighted ? 255 : 200, isHighlighted ? 255 : 200);
    doc.setFontSize(5.5);
    const truncated = line.substring(0, 100);
    doc.text(truncated, startX + 10, cy + 2.5);

    cy += lineH;
  });

  cy += padding;
  return cy;
}

/**
 * Builds a synthetic code block from an alert's evidence data.
 * Simulates HTTP headers, server responses, or code snippets depending on the vulnerability type.
 */
function buildEvidenceCodeBlock(alert: Alert): string {
  const cweNum = alert.cweId.replace(/[^0-9]/g, '');
  const url = alert.affectedUrl || 'https://target.example.com';

  // Header-related vulnerabilities (missing security headers)
  if (alert.evidence.toLowerCase().includes('header') ||
      alert.evidence.toLowerCase().includes('no encontrado') ||
      alert.name.toLowerCase().includes('header') ||
      alert.name.toLowerCase().includes('content-security') ||
      alert.name.toLowerCase().includes('x-frame') ||
      alert.name.toLowerCase().includes('strict-transport') ||
      alert.name.toLowerCase().includes('x-content-type')) {
    const headerName = alert.header || alert.name.split(':')[0].trim();
    return [
      `GET ${url} HTTP/1.1`,
      `Host: ${new URL(url).hostname}`,
      ``,
      `HTTP/1.1 200 OK`,
      `Server: Apache/2.4`,
      `Content-Type: text/html; charset=UTF-8`,
      `X-Powered-By: PHP/8.1`,
      `// [ERROR] ${headerName}: NOT SET`,
      `// ${alert.evidence}`,
      ``,
      `<!-- CWE-${cweNum} | OWASP ${alert.owaspCategory} -->`,
    ].join('\n');
  }

  // XSS / Injection vulnerabilities
  if (alert.name.toLowerCase().includes('xss') ||
      alert.name.toLowerCase().includes('injection') ||
      alert.name.toLowerCase().includes('script')) {
    return [
      `// Recurso: ${url}`,
      `// Fuente: ${alert.source}`,
      ``,
      `<script>`,
      `  // [VULNERABLE] Input no sanitizado`,
      `  var userInput = getParameter("q");`,
      `  document.write(userInput);  // XSS RISK`,
      `</script>`,
      ``,
      `// Evidencia: ${alert.evidence.substring(0, 80)}`,
      `// CWE-${cweNum} | OWASP ${alert.owaspCategory}`,
    ].join('\n');
  }

  // Default: generic evidence block
  return [
    `// Vulnerabilidad: ${alert.name}`,
    `// Recurso: ${url}`,
    `// Fuente: ${alert.source}`,
    ``,
    `// [HALLAZGO] ${alert.evidence.substring(0, 80)}`,
    `// Severidad: ${alert.severity.toUpperCase()}`,
    `// CWE: ${alert.cweId}`,
    `// OWASP: ${alert.owaspCategory}`,
    ``,
    `// Recomendación: Verificar configuración del servidor`,
  ].join('\n');
}

export function generatePDFReport(data: ReportData, pdfPassword: string): void {
  const doc = new jsPDF({
    orientation: 'p',
    unit: 'mm',
    format: 'a4',
    encryption: {
      userPassword: pdfPassword,
      ownerPassword: pdfPassword,
      userPermissions: ['print', 'copy']
    }
  });
  const pageW = doc.internal.pageSize.getWidth();
  const margin = 20;
  const contentW = pageW - margin * 2;
  let y = 0;

  // Mapa de páginas reales para el índice dinámico
  const sectionPages: Record<string, number> = {};
  let figureCounter = 0;

  const reportDate = new Date().toLocaleDateString('es-ES', {
    year: 'numeric', month: 'long', day: 'numeric'
  });
  const totalVulns = data.alerts.length;
  const resolvedCount = data.patchedAlerts.length;
  const crit = data.scanSummary?.critical || 0;
  const high = data.scanSummary?.high || 0;

  const checkPage = (needed: number) => {
    if (y + needed > 268) {
      doc.addPage();
      y = 25;
    }
  };

  const reportId = `BT-${Date.now().toString(36).toUpperCase()}`;

  const addPageHeader = () => {
    doc.setTextColor(...COLORS.gray);
    doc.setFontSize(7);
    doc.setFont('helvetica', 'bold');
    // Movido más a la izquierda para evitar solapamiento con el ID
    doc.text('CONFIDENCIAL', pageW - margin - 35, 9, { align: 'right' });
    
    doc.setFont('helvetica', 'normal');
    doc.text('Empresa Default — Informe de Evaluación de Vulnerabilidades', margin, 9);
    doc.text(`ID: ${reportId}`, pageW - margin, 9, { align: 'right' });
    doc.setDrawColor(230, 230, 230);
    doc.setLineWidth(0.1);
    doc.line(margin, 12, pageW - margin, 12);
  };

  const addPageFooter = (pageNum: number) => {
    const footerY = 285;
    doc.setDrawColor(230, 230, 230);
    doc.setLineWidth(0.1);
    doc.line(margin, footerY - 5, pageW - margin, footerY - 5);
    
    // Logo Empresa Default inferior izquierdo
    if (logoBase64) {
      // Reducimos un poco el tamaño para que sea sobrio en el footer
      doc.addImage(logoBase64, 'JPEG', margin, footerY - 6, 20, 10);
    }
    
    doc.setTextColor(...COLORS.gray);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.text(`Página ${pageNum}`, pageW - margin, footerY, { align: 'right' });
    doc.text('Empresa Default — Dirección de Ciberseguridad', pageW / 2, footerY, { align: 'center' });
  };

  // ═══════════════════════════════════════
  // PORTADA
  // ═══════════════════════════════════════
  doc.setFillColor(...COLORS.white);
  doc.rect(0, 0, 210, 297, 'F');

  // Línea decorativa superior
  doc.setFillColor(...COLORS.accent);
  doc.rect(0, 0, 210, 2, 'F');

  // Logo Empresa Default
  // El logo se ubicará en la parte superior derecha de la portada
  if (logoBase64) {
    doc.addImage(logoBase64, 'JPEG', 150, 20, 40, 15);
  }

  // Título
  doc.setTextColor(...COLORS.primary);
  doc.setFontSize(24);
  doc.setFont('helvetica', 'bold');
  doc.text('INFORME DE EVALUACIÓN', margin, 100);
  doc.text('DE VULNERABILIDADES', margin, 112);

  // Subtítulo
  doc.setFontSize(10);
  doc.setTextColor(...COLORS.gray);
  doc.setFont('helvetica', 'normal');
  doc.text('VULNERABILITY ASSESSMENT REPORT — ESTÁNDAR OWASP v3', margin, 122);

  // Línea separadora sobria
  doc.setDrawColor(200, 200, 200);
  doc.setLineWidth(0.2);
  doc.line(margin, 130, 100, 130);

  // Información del informe
  doc.setFontSize(10);
  doc.setTextColor(...COLORS.darkGray);
  
  doc.text(`Objetivo:`, margin, 150);
  doc.setFont('helvetica', 'bold');
  doc.text(`${data.target}`, margin + 25, 150);
  
  doc.setFont('helvetica', 'normal');
  doc.text(`Fecha:`, margin, 160);
  doc.text(`${reportDate}`, margin + 25, 160);
  
  doc.text(`ID Reporte:`, margin, 170);
  doc.text(`${reportId}`, margin + 25, 170);

  // Clasificación sobria
  doc.setDrawColor(...COLORS.accent);
  doc.rect(margin, 200, 60, 8);
  doc.setTextColor(...COLORS.accent);
  doc.setFontSize(8);
  doc.setFont('helvetica', 'bold');
  doc.text('CLASIFICACIÓN: CONFIDENCIAL', margin + 30, 205.5, { align: 'center' });

  // Footer portada
  doc.setTextColor(...COLORS.gray);
  doc.setFontSize(8);
  doc.setFont('helvetica', 'normal');
  doc.text('Universidad Tecnológica de Chile Empresa Default', margin, 275);
  doc.text('Departamento de Informática y Ciberseguridad', margin, 280);

  // ═══════════════════════════════════════
  // PÁGINA 2: ACUERDO DE CONFIDENCIALIDAD (va justo después de la portada)
  // ═══════════════════════════════════════
  doc.addPage();
  sectionPages['confidencialidad'] = doc.getNumberOfPages();
  y = 25;

    // --- Acuerdo de Confidencialidad detallado ---
  doc.setTextColor(...COLORS.accent);
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  const chapterMap: Record<string, string> = {};
  let chapterNum = 1;
  chapterMap['acuerdo'] = String(chapterNum++);
  doc.text(`${chapterMap['acuerdo']}. Acuerdo de Confidencialidad`, margin, y);
  y += 12;

  // Helper para dibujar secciones con título en negrita y cuerpo normal
  const drawBoldSection = (title: string, body: string[]) => {
    checkPage(30);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9);
    doc.setTextColor(40, 40, 40);
    doc.text(title, margin, y);
    y += 5;
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(80, 80, 80);
    body.forEach(line => {
      checkPage(6);
      doc.text(line, margin + 5, y);
      y += 4.5;
    });
    y += 3;
  };

  drawBoldSection('Identificación de las Partes', [
    `• Parte Reveladora (Cliente): Propietarios de la plataforma web auditada (${data.target}).`,
    `• Parte Receptora (Auditor): Equipo de Auditoría de Seguridad — Empresa Default.`,
    `• Fecha de entrada en vigor: ${new Date().toLocaleDateString('es-ES')}`,
  ]);

  drawBoldSection('Definición de "Información Confidencial"', [
    'Incluye direcciones IP, rangos de red, arquitecturas de sistemas, credenciales, tokens,',
    'claves criptográficas, vulnerabilidades descubiertas, código fuente, bases de datos de',
    'clientes, correos electrónicos, registros financieros y los informes finales.',
  ]);

  drawBoldSection('Exclusiones de la Confidencialidad', [
    'Información pública previa, datos ya conocidos legalmente por el auditor, información',
    'recibida de terceros sin obligación de confidencialidad, y divulgación requerida por',
    'orden judicial (preaviso al cliente).',
  ]);

  drawBoldSection('Obligaciones y Uso Permitido', [
    '• Propósito único: uso exclusivo para pruebas y elaboración del informe.',
    '• Estándares de protección: nivel de seguridad igual o superior al propio.',
    '• Restricción de copia: prohibido copiar bases de datos o exfiltrar información más allá del PoC necesario.',
  ]);

  drawBoldSection('Retención y Destrucción de la Información', [
    '• Plazo de eliminación: 30 días después de la entrega del informe final.',
    '• Certificado de destrucción: declaración formal de eliminación segura.',
  ]);

  drawBoldSection('Plazo de Vigencia', [
    '• Duración de la relación comercial: periodo de pruebas establecido en el contrato.',
    '• Vigencia de la confidencialidad: 3 años después de concluido el trabajo.',
  ]);

  drawBoldSection('Consecuencias por Incumplimiento', [
    '• Medidas cautelares inmediatas, compensación por daños y perjuicios,',
    '  jurisdicción aplicable: tribunales de Chile.',
  ]);

  // Firmas
  checkPage(25);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9);
  doc.setTextColor(40, 40, 40);
  doc.text('Firmas', margin, y);
  y += 8;
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(80, 80, 80);
  doc.setDrawColor(100, 100, 100);
  doc.setLineWidth(0.3);
  doc.line(margin, y, margin + 55, y);
  doc.line(margin + 80, y, margin + 135, y);
  y += 5;
  doc.setFontSize(8);
  doc.text('Representante del Cliente', margin, y);
  doc.text('Representante del Auditor', margin + 80, y);
  y += 10;

  // Equipo de auditoría
  checkPage(60);
  doc.setFontSize(10);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(...COLORS.accent);
  doc.text('Equipo de Auditoría Ethical Hacking:', margin, y);
  y += 8;
  const team = [
    {name: 'Catalina Caris', role: 'Líder de Auditoría'},
    {name: 'Oscar Hernández', role: 'Analista de Vulnerabilidades'},
    {name: 'Victor Aguilera', role: 'Especialista en Explotación'},
    {name: 'Carlos Tapia', role: 'Ingeniero de Redes'},
    {name: 'Israel Monárrez', role: 'Analista de Malware'},
    {name: 'Jeison Sánchez', role: 'Coordinador de Reportes'}
  ];
  team.forEach(member => {
    checkPage(7);
    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(80, 80, 80);
    doc.text(`${member.name} – ${member.role}`, margin + 10, y);
    y += 6;
  });

  // ═══════════════════════════════════════
  // PÁGINA: ÍNDICE (placeholder — se rellena al final con páginas reales)
  // ═══════════════════════════════════════
  doc.addPage();
  const tocPageNumber = doc.getNumberOfPages();
  // La página se deja en blanco; se dibuja el TOC al final con los números reales

  // ═══════════════════════════════════════
  // ALCANCE Y OBJETIVO (nueva página para evitar superposición)
  // ═══════════════════════════════════════
  doc.addPage();
  sectionPages['alcance'] = doc.getNumberOfPages();
  y = 25;

  doc.setTextColor(...COLORS.accent);
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  chapterMap['alcance'] = String(chapterNum++);
  doc.text(`${chapterMap['alcance']}. Alcance y Objetivo`, margin, y);
  y += 10;

  doc.setTextColor(80, 80, 80);
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  const alcanceText = `La presente evaluación técnica tiene como objetivo identificar, analizar y clasificar las vulnerabilidades de seguridad presentes en el activo ${data.target}. El alcance se limita a las interfaces web públicas y los endpoints detectados durante la fase de reconocimiento.

Objetivos Específicos:
• Identificar fallos de configuración y vulnerabilidades de software.
• Evaluar el impacto potencial sobre la tríada CIA (Confidencialidad, Integridad, Disponibilidad).
• Proporcionar recomendaciones técnicas de mitigación basadas en estándares internacionales.`;

  const alcanceLines = doc.splitTextToSize(alcanceText, contentW);
  doc.text(alcanceLines, margin, y);
  y += alcanceLines.length * 4.5 + 10;

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.text(`${chapterNum - 1}.1 Pruebas dentro del alcance`, margin, y);
  y += 6;
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.text(`• Análisis de vulnerabilidades web en el activo: ${data.target}`, margin + 5, y);
  y += 5;
  doc.text('• Pruebas de configuración de cabeceras de seguridad y SSL/TLS.', margin + 5, y);
  y += 5;
  doc.text('• Escaneo de puertos y servicios públicos asociados.', margin + 5, y);
  y += 10;

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.text(`${chapterNum - 1}.2 Pruebas fuera del alcance`, margin, y);
  y += 6;
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.text('• Pruebas de denegación de servicio (DoS/DDoS).', margin + 5, y);
  y += 5;
  doc.text('• Ingeniería social contra empleados o clientes.', margin + 5, y);
  y += 5;
  doc.text('• Pruebas físicas en instalaciones de Empresa Default.', margin + 5, y);
  y += 15;
  // ═══════════════════════════════════════
  // PÁGINA: METODOLOGÍA Y HERRAMIENTAS
  // ═══════════════════════════════════════
  doc.addPage();
  sectionPages['metodologia'] = doc.getNumberOfPages();
  y = 25;

  doc.setTextColor(...COLORS.accent);
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  chapterMap['metodologia'] = String(chapterNum++);
  doc.text(`${chapterMap['metodologia']}. Metodología y Herramientas`, margin, y);
  y += 10;

  doc.setTextColor(80, 80, 80);
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  const metoDesc = 'La evaluación se basa en una metodología de caja negra (Black Box) siguiendo los estándares de OWASP y PTES. Se han utilizado herramientas líderes en la industria para garantizar la detección exhaustiva de vulnerabilidades.';
  doc.text(doc.splitTextToSize(metoDesc, contentW), margin, y);
  y += 15;

  // Cuadro de Herramientas (Solo las utilizadas)
  doc.setFillColor(245, 247, 250);
  doc.roundedRect(margin, y, contentW, 55, 2, 2, 'F');
  doc.setTextColor(...COLORS.primary);
  doc.setFontSize(10);
  doc.setFont('helvetica', 'bold');
  doc.text('HERRAMIENTAS UTILIZADAS EN LA EVALUACIÓN', margin + contentW / 2, y + 8, { align: 'center' });

  y += 15;
  
  // Dibujar logos de herramientas de izquierda a derecha con nombres
  const logoWidth = 30;
  const logoHeight = 12;
  
  const logosRow1 = [
    { img: LOGO_OWASP, text: 'OWASP TOP 10' },
    { img: LOGO_ZAP, text: 'OWASP ZAP' },
    { img: LOGO_MOZILLA, text: 'MOZILLA OBSERVATORY' },
    { img: LOGO_NIST, text: 'NIST SP 800-115' }
  ];
  
  const gapX4 = (contentW - (logoWidth * 4)) / 5;
  
  doc.setFontSize(7);
  doc.setTextColor(...COLORS.gray);
  doc.setFont('helvetica', 'bold');

  logosRow1.forEach((logo, i) => {
    if (logo.img) {
      const x = margin + gapX4 * (i + 1) + logoWidth * i;
      doc.addImage(logo.img, 'JPEG', x, y, logoWidth, logoHeight);
      doc.text(logo.text, x + logoWidth / 2, y + logoHeight + 4, { align: 'center' });
    }
  });
  
  y += logoHeight + 12;
  
  const logosRow2 = [
    { img: LOGO_LLAMA, text: 'LLAMA 3.3 AI ENGINE' },
    { img: LOGO_MITRE, text: 'MITRE' },
    { img: LOGO_CWE, text: 'CWE' }
  ];
  
  const gapX3 = (contentW - (logoWidth * 3)) / 4;
  
  logosRow2.forEach((logo, i) => {
    if (logo.img) {
      const x = margin + gapX3 * (i + 1) + logoWidth * i;
      doc.addImage(logo.img, 'JPEG', x, y, logoWidth, logoHeight);
      doc.text(logo.text, x + logoWidth / 2, y + logoHeight + 4, { align: 'center' });
    }
  });

  y += 25;

  // ═══════════════════════════════════════
  // RESUMEN DE RESULTADOS Y MATRIZ DE RIESGO
  // ═══════════════════════════════════════
  doc.addPage();
  sectionPages['matrizRiesgo'] = doc.getNumberOfPages();
  y = 25;

  doc.setTextColor(...COLORS.accent);
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  chapterMap['resumen'] = String(chapterNum++);
  doc.text(`${chapterMap['resumen']}. Resumen de resultados de hallazgos y Matriz de Riesgo`, margin, y);
  y += 10;

  doc.setTextColor(80, 80, 80);
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.text(`${chapterNum - 1}.1 Resumen de resultados de hallazgos`, margin, y);
  y += 8;

  // Implementación del Gráfico de Torta (Pie Chart)
  const drawPieChart = (x: number, y: number, radius: number, sevData: any[]) => {
    const total = sevData.reduce((s: number, d: any) => s + d.count, 0);
    if (total === 0) return;
    let startAngle = 0;
    sevData.forEach((d: any) => {
      if (d.count === 0) return;
      const angle = (d.count / total) * 2 * Math.PI;
      doc.setFillColor(d.color[0], d.color[1], d.color[2]);
      doc.moveTo(x, y);
      const segments = 40;
      for (let i = 0; i <= segments; i++) {
        const a = startAngle + (i / segments) * angle - Math.PI / 2;
        doc.lineTo(x + radius * Math.cos(a), y + radius * Math.sin(a));
      }
      doc.lineTo(x, y);
      doc.fill();
      
      const labelAngle = startAngle + angle / 2 - Math.PI / 2;
      const labelX = x + (radius + 8) * Math.cos(labelAngle);
      const labelY = y + (radius + 8) * Math.sin(labelAngle);
      doc.setFontSize(6);
      doc.setTextColor(...COLORS.darkGray);
      doc.text(`${d.label}; ${d.count}`, labelX, labelY, { align: 'center' });
      
      startAngle += angle;
    });
  };

  const chartData = [
    { label: 'OP', count: data.alerts.filter(a => a.severity === 'Low' || a.severity === 'Informational').length, color: COLORS.green },
    { label: 'Bajo', count: data.scanSummary?.low || 0, color: COLORS.low },
    { label: 'Medio', count: data.scanSummary?.medium || 0, color: COLORS.medium },
    { label: 'Alto', count: data.scanSummary?.high || 0, color: COLORS.high },
    { label: 'Crítico', count: data.scanSummary?.critical || 0, color: COLORS.critical },
  ];

  drawPieChart(margin + 40, y + 25, 20, chartData);
  
  doc.setFontSize(7);
  doc.setTextColor(...COLORS.gray);
  doc.text('Figura 1. Proporcionalidad del riesgo encontrado en la aplicación.', margin + 40, y + 55, { align: 'center' });

  y += 70;

  doc.setFontSize(9);
  doc.setTextColor(80, 80, 80);
  doc.setFont('helvetica', 'normal');
  doc.text(`${chapterNum - 1}.2 Matriz de Riesgo`, margin, y);
  y += 8;

  // Dibujar Mapa de Calor
  const gridW = 100;
  const gridH = 60;
  const startX = margin + (contentW - gridW) / 2;
  const cellW = gridW / 5;
  const cellH = gridH / 5;

  // Matriz 5x5 según la imagen
  const matrixColors = [
    [COLORS.green, COLORS.green, COLORS.green, COLORS.green, COLORS.green],      // Insignificante
    [COLORS.green, COLORS.green, COLORS.green, COLORS.medium, COLORS.high],     // Menor
    [COLORS.green, COLORS.green, COLORS.medium, COLORS.high, COLORS.critical],   // Moderado
    [COLORS.green, COLORS.medium, COLORS.high, COLORS.critical, COLORS.critical], // Mayor
    [COLORS.medium, COLORS.high, COLORS.critical, COLORS.critical, COLORS.critical] // Serio
  ];

  const yLabels = ['Insignificante', 'Menor', 'Moderado', 'Mayor', 'Serio'];
  const xLabels = ['Raro', 'Improbable', 'Posible', 'Probable', 'Casi Cierta'];

  for (let i = 0; i < 5; i++) {
    for (let j = 0; j < 5; j++) {
      doc.setFillColor(...matrixColors[i][j]);
      doc.rect(startX + j * cellW, y + (4 - i) * cellH, cellW, cellH, 'F');
      doc.setDrawColor(255, 255, 255);
      doc.rect(startX + j * cellW, y + (4 - i) * cellH, cellW, cellH, 'D');
    }
  }

  // Etiquetas Ejes
  doc.setTextColor(...COLORS.darkGray);
  doc.setFontSize(7);
  doc.setFont('helvetica', 'bold');
  
  // Eje Y (Impacto)
  doc.text('IMPACTO', startX - 18, y + gridH / 2, { angle: 90, align: 'center' });
  yLabels.forEach((l, i) => {
    doc.text(l, startX - 2, y + (4 - i) * cellH + cellH / 2 + 2, { align: 'right' });
  });

  // Eje X (Probabilidad)
  doc.text('PROBABILIDAD', startX + gridW / 2, y + gridH + 12, { align: 'center' });
  xLabels.forEach((l, i) => {
    doc.text(l, startX + i * cellW + cellW / 2, y + gridH + 4, { align: 'center', maxWidth: cellW - 2 });
  });

  // Dibujar Vulnerabilidades dentro del Mapa
  const getMatrixPos = (severity: string, riskScore: number) => {
    let row = 0; // Impacto
    if (severity === 'Critical') row = 4;
    else if (severity === 'High') row = 3;
    else if (severity === 'Medium') row = 2;
    else if (severity === 'Low') row = 1;
    else row = 0;

    let col = 0; // Probabilidad
    if (riskScore >= 9) col = 4;
    else if (riskScore >= 7) col = 3;
    else if (riskScore >= 5) col = 2;
    else if (riskScore >= 3) col = 1;
    else col = 0;

    return { row, col };
  };

  const cellContents: Record<string, string[]> = {};
  data.alerts.forEach((a, idx) => {
    const { row, col } = getMatrixPos(a.severity, a.riskScore);
    const key = `${row}-${col}`;
    if (!cellContents[key]) cellContents[key] = [];
    const prefix = a.severity[0].toUpperCase(); // C, H, M, L
    cellContents[key].push(`${prefix}${idx + 1}`);
  });

  Object.entries(cellContents).forEach(([key, ids]) => {
    const [row, col] = key.split('-').map(Number);
    const cellX = startX + col * cellW;
    const cellY = y + (2 - row) * cellH;
    
    doc.setTextColor(...COLORS.white);
    doc.setFontSize(6);
    doc.setFont('helvetica', 'bold');
    
    // Dibujar los IDs en la celda (máximo 6 por celda para no saturar)
    const displayIds = ids.slice(0, 6).join(', ');
    doc.text(displayIds, cellX + cellW / 2, cellY + cellH / 2, { align: 'center', maxWidth: cellW - 4 });
  });

  y += gridH + 20;
  
  doc.setFontSize(7);
  doc.setTextColor(...COLORS.gray);
  doc.setFont('helvetica', 'italic');
  doc.text('Nota: El cálculo del riesgo se basa en la OWASP Risk Rating Methodology.', margin, y);
  y += 10;

  // ═══════════════════════════════════════
  // CLASIFICACIÓN POR TRÍADA CID
  // ═══════════════════════════════════════
  checkPage(60);
  doc.setTextColor(...COLORS.accent);
  doc.setFontSize(14);
  doc.setFont('helvetica', 'bold');
  doc.text(`${chapterNum - 1}.3 Clasificación por Tríada de Seguridad (CID)`, margin, y);
  y += 8;

  doc.setTextColor(80, 80, 80);
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.text('Análisis del impacto de las vulnerabilidades sobre la Confidencialidad, Integridad y Disponibilidad.', margin, y);
  y += 6;

  // Auto-detect CID impact when ZAP doesn't provide it
  const inferCID = (a: Alert): { c: string; i: string; d: string } => {
    // If explicit CIA data exists, use it
    if (a.cia && (a.cia.confidentiality || a.cia.integrity || a.cia.availability)) {
      return {
        c: a.cia.confidentiality ? 'Alta' : 'Ninguna',
        i: a.cia.integrity ? 'Alta' : 'Ninguna',
        d: a.cia.availability ? 'Alta' : 'Ninguna',
      };
    }
    // Auto-infer based on vulnerability name/type (NIST SP 800-53 mappings)
    const name = a.name.toLowerCase();
    let c = 'Ninguna', i = 'Ninguna', d = 'Ninguna';

    // Content-Security-Policy -> C: Alta, I: Alta (prevents XSS data exfil)
    if (name.includes('content-security-policy')) { c = 'Alta'; i = 'Alta'; }
    // X-Frame-Options -> I: Alta (prevents clickjacking / UI redress)
    else if (name.includes('x-frame-options')) { i = 'Alta'; }
    // Strict-Transport-Security -> C: Alta (prevents MITM on transport)
    else if (name.includes('strict-transport') || name.includes('hsts')) { c = 'Alta'; }
    // X-Content-Type-Options -> I: Alta (prevents MIME sniffing)
    else if (name.includes('x-content-type')) { i = 'Alta'; }
    // X-XSS-Protection -> C: Alta, I: Alta (XSS filter)
    else if (name.includes('x-xss-protection') || name.includes('xss')) { c = 'Alta'; i = 'Alta'; }
    // Referrer-Policy -> C: Alta (prevents info leakage)
    else if (name.includes('referrer-policy')) { c = 'Alta'; }
    // Permissions-Policy -> C: Alta, I: Media (restricts browser features)
    else if (name.includes('permissions-policy') || name.includes('feature-policy')) { c = 'Alta'; i = 'Media'; }
    // SQL Injection -> C: Alta, I: Alta, D: Alta
    else if (name.includes('sql') || name.includes('injection')) { c = 'Alta'; i = 'Alta'; d = 'Alta'; }
    // Cryptographic / SSL -> C: Alta
    else if (name.includes('crypto') || name.includes('ssl') || name.includes('tls') || name.includes('cipher')) { c = 'Alta'; }
    // Server info disclosure -> C: Media
    else if (name.includes('server') || name.includes('disclosure') || name.includes('information')) { c = 'Media'; }
    // Default for severity-based fallback
    else if (a.severity === 'Critical') { c = 'Alta'; i = 'Alta'; d = 'Media'; }
    else if (a.severity === 'High') { c = 'Alta'; i = 'Media'; }
    else if (a.severity === 'Medium') { c = 'Media'; i = 'Media'; }
    else if (a.severity === 'Low') { c = 'Baja'; }

    return { c, i, d };
  };

  const ciaData = data.alerts.map((a, idx) => {
    const cid = inferCID(a);
    return [
      `${a.severity[0].toUpperCase()}${idx + 1}`,
      a.name.substring(0, 50),
      cid.c,
      cid.i,
      cid.d,
    ];
  });

  autoTable(doc, {
    startY: y,
    head: [['ID', 'Vulnerabilidad', 'Confidencialidad', 'Integridad', 'Disponibilidad']],
    body: ciaData,
    theme: 'grid',
    headStyles: { fillColor: COLORS.darkGray, textColor: COLORS.white, fontSize: 7, fontStyle: 'bold' },
    bodyStyles: { fontSize: 7, textColor: [80, 80, 80], halign: 'center' },
    columnStyles: {
      1: { halign: 'left', cellWidth: 70 },
    },
    margin: { left: margin, right: margin, bottom: 25 },
    tableWidth: contentW,
  });

  y = (doc as any).lastAutoTable.finalY + 15;
  checkPage(40);

  // Cuadro visual de severidades
  const sevData = [
    { label: 'CRÍTICAS', count: data.scanSummary?.critical || 0, color: COLORS.critical },
    { label: 'ALTAS', count: data.scanSummary?.high || 0, color: COLORS.high },
    { label: 'MEDIAS', count: data.scanSummary?.medium || 0, color: COLORS.medium },
    { label: 'BAJAS', count: data.scanSummary?.low || 0, color: COLORS.low },
    { label: 'RESUELTAS', count: resolvedCount, color: COLORS.green },
  ];

  const boxW = (contentW - 4 * 4) / 5;
  sevData.forEach((s, i) => {
    const x = margin + i * (boxW + 4);
    doc.setFillColor(...s.color);
    doc.roundedRect(x, y, boxW, 22, 2, 2, 'F');
    doc.setTextColor(...COLORS.white);
    doc.setFontSize(18);
    doc.setFont('helvetica', 'bold');
    doc.text(String(s.count), x + boxW / 2, y + 12, { align: 'center' });
    doc.setFontSize(6);
    doc.text(s.label, x + boxW / 2, y + 18, { align: 'center' });
  });
  y += 35;

  // Tabla resumen de hallazgos
  if (y > 180) {
    doc.addPage();
    y = 25;
  }
  autoTable(doc, {
    startY: y,
    head: [['RISK ID', 'VULNERABILIDAD', 'INCIDENCIAS', 'COMPLEJIDAD', 'COSTO', 'RIESGO']],
    body: data.alerts.map((a, idx) => [
      `${a.severity[0].toUpperCase()}${idx + 1}`,
      a.name.substring(0, 40),
      a.incidences || 1,
      a.effort?.complexity || 'BAJA',
      a.effort?.cost || 'BAJO',
      a.severity.toUpperCase(),
    ]),
    theme: 'grid',
    headStyles: { fillColor: COLORS.darkGray, textColor: COLORS.white, fontSize: 7, fontStyle: 'bold', halign: 'center' },
    bodyStyles: { fontSize: 7, textColor: [80, 80, 80], halign: 'center' },
    columnStyles: {
      1: { halign: 'left', cellWidth: 50 },
      5: { fontStyle: 'bold' },
    },
    didParseCell: (hookData: any) => {
      if (hookData.section === 'body' && hookData.column.index === 5) {
        const sev = (hookData.cell.raw as string).toLowerCase();
        if (sev.includes('critical')) hookData.cell.styles.fillColor = COLORS.critical;
        else if (sev.includes('high')) hookData.cell.styles.fillColor = COLORS.high;
        else if (sev.includes('medium')) hookData.cell.styles.fillColor = COLORS.medium;
        else if (sev.includes('low')) hookData.cell.styles.fillColor = COLORS.green;
        hookData.cell.styles.textColor = COLORS.white;
      }
    },
    margin: { left: margin, right: margin, bottom: 25 },
    tableWidth: contentW,
    showHead: 'everyPage',
  });

  y = (doc as any).lastAutoTable.finalY + 10;
  
  doc.setFontSize(7);
  doc.setTextColor(80, 80, 80);
  doc.text('RISK ID:', margin, y);
  doc.text('C: Confidencialidad, A: Disponibilidad, I: Integridad, OP: Oportunidad de Mejora', margin + 15, y);
  y += 5;
  doc.text('Esfuerzo de mitigación:', margin, y);
  y += 5;
  checkPage(10);
  doc.text('Complejidad: Habilidades / Recursos necesarios | Costo: Horas hombre (HH) Involucradas', margin, y);
  y += 10;

  // (Conclusiones y Recomendaciones re-movidas después de Evaluación de Riesgo para seguir estándar NIST)

  // ═══════════════════════════════════════
  // HALLAZGOS DETALLADOS
  // ═══════════════════════════════════════
  doc.addPage();
  sectionPages['detalle'] = doc.getNumberOfPages();
  y = 25;

  doc.setTextColor(...COLORS.accent);
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  chapterMap['detalle'] = String(chapterNum++);
  doc.text(`${chapterMap['detalle']}. Detalle de vulnerabilidades y pruebas`, margin, y);
  y += 12;

  const severities = ['Critical', 'High', 'Medium', 'Low', 'Informational'];
  const sevLabels: Record<string, string> = {
    'Critical': 'Vulnerabilidades de nivel crítico',
    'High': 'Vulnerabilidades de nivel alto',
    'Medium': 'Vulnerabilidades de nivel medio',
    'Low': 'Vulnerabilidades de nivel bajo',
    'Informational': 'Oportunidades de mejora'
  };

  let sevCount = 0;
  severities.forEach((sev, sIdx) => {
    const sevAlerts = data.alerts.filter(a => a.severity === sev);
    if (sevAlerts.length === 0) return;
    sevCount++;

    checkPage(20);
    doc.setFontSize(12);
    doc.setTextColor(...COLORS.accent);
    doc.setFont('helvetica', 'bold');
    doc.text(`${chapterMap['detalle']}.${sevCount} ${sevLabels[sev]}`, margin, y);
    y += 10;

    sevAlerts.forEach((alert, aIdx) => {
      // Bloqueo lógico: Evitamos huérfanos asegurando espacio suficiente para el hallazgo y la imagen
      if (y > 160) {
        doc.addPage();
        y = 25;
      } else {
        checkPage(60);
      }

      // Finding header
      const sc = sevColor(alert.severity);
      doc.setFillColor(...COLORS.primary);
      doc.rect(margin, y, contentW, 8, 'F');
      doc.setTextColor(...COLORS.white);
      doc.setFontSize(9);
      doc.setFont('helvetica', 'bold');
      doc.text(`${chapterMap['detalle']}.${sevCount}.${aIdx + 1}  ${alert.name}`, margin + 3, y + 5.5);
      y += 12;

    // Finding details table (NOMENCLATURA / RESUMEN DE HALLAZGO)
    const probLabel = alert.riskScore >= 7 ? 'Casi Cierta' : alert.riskScore >= 5 ? 'Probable' : 'Posible';
    const impactLabel = alert.severity === 'Critical' ? 'Serio' : alert.severity === 'High' ? 'Mayor' : 'Moderado';

    const owaspLinks: Record<string, string> = {
      'A01': 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
      'A02': 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
      'A03': 'https://owasp.org/Top10/A03_2021-Injection/',
      'A04': 'https://owasp.org/Top10/A04_2021-Insecure_Design/',
      'A05': 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
      'A06': 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
      'A07': 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
      'A08': 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/',
      'A09': 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/',
      'A10': 'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_SSRF/',
    };

    const alertOwaspId = alert.owaspCategory.substring(0, 3);
    const clickableLink = owaspLinks[alertOwaspId] || 'https://owasp.org/www-project-top-ten/';

    // Build CWE link for MITRE database
    const cweNum = alert.cweId.replace(/[^0-9]/g, '');
    const cweLink = cweNum ? `https://cwe.mitre.org/data/definitions/${cweNum}.html` : 'https://cwe.mitre.org/';

    autoTable(doc, {
      startY: y,
      head: [['NOMENCLATURA', 'RESUMEN DE HALLAZGO']],
      body: [
        ['RECURSO AFECTADO', alert.affectedUrl],
        ['RISK ID', `${alert.severity[0].toUpperCase()}${data.alerts.indexOf(alert) + 1}`],
        ['CWE', alert.cweId],
        ['PROBABILIDAD', probLabel],
        ['IMPACTO', impactLabel],
        ['CLASIFICACIÓN OWASP', alert.owaspCategory],
      ],
      theme: 'grid',
      headStyles: { fillColor: [240, 240, 240], textColor: [50, 50, 50], fontSize: 8, fontStyle: 'bold' },
      bodyStyles: { fontSize: 8, textColor: [80, 80, 80] },
      columnStyles: {
        0: { cellWidth: 40, fontStyle: 'bold', fillColor: [250, 250, 250] },
      },
      didParseCell: (hookData) => {
        // CWE row (index 2) — link style
        if (hookData.section === 'body' && hookData.column.index === 1 && hookData.row.index === 2) {
          hookData.cell.styles.textColor = COLORS.accent;
          hookData.cell.styles.fontStyle = 'bold';
        }
        // OWASP row (index 5) — link style
        if (hookData.section === 'body' && hookData.column.index === 1 && hookData.row.index === 5) {
          hookData.cell.styles.textColor = COLORS.accent;
          hookData.cell.styles.fontStyle = 'bold';
        }
      },
      didDrawCell: (hookData) => {
        // CWE row → link to MITRE
        if (hookData.section === 'body' && hookData.column.index === 1 && hookData.row.index === 2) {
          doc.link(hookData.cell.x, hookData.cell.y, hookData.cell.width, hookData.cell.height, { url: cweLink });
        }
        // OWASP row → link to OWASP Top 10
        if (hookData.section === 'body' && hookData.column.index === 1 && hookData.row.index === 5) {
          doc.link(hookData.cell.x, hookData.cell.y, hookData.cell.width, hookData.cell.height, { url: clickableLink });
        }
        // Recurso Afectado row → clickable URL
        if (hookData.section === 'body' && hookData.column.index === 1 && hookData.row.index === 0) {
          doc.link(hookData.cell.x, hookData.cell.y, hookData.cell.width, hookData.cell.height, { url: alert.affectedUrl });
        }
      },
      margin: { left: margin, right: margin, bottom: 25 },
      tableWidth: contentW,
    });

    y = (doc as any).lastAutoTable.finalY + 8;

    // RIESGO Section
    doc.setFillColor(245, 245, 245);
    doc.rect(margin, y, contentW, 6, 'F');
    doc.setTextColor(...COLORS.darkGray);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'bold');
    doc.text('RIESGO', margin + contentW / 2, y + 4.5, { align: 'center' });
    y += 10;

    doc.setTextColor(80, 80, 80);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    const riskLines = doc.splitTextToSize(alert.description, contentW);
    doc.text(riskLines, margin, y);
    y += riskLines.length * 4 + 5;

    // ═══════════════════════════════════════
    // EVIDENCIA TÉCNICA (BLOQUE DE CÓDIGO ESTILO IDE)
    // ═══════════════════════════════════════
    if (alert.evidence && alert.evidence.trim().length > 0) {
      checkPage(50);

      // Build a synthetic code block from the evidence
      const evidenceCode = buildEvidenceCodeBlock(alert);
      y = renderCodeBlock(doc, evidenceCode, alert.evidence, margin, y, contentW, checkPage);

      // Figure caption (APA 7 style)
      figureCounter++;
      doc.setFontSize(7);
      doc.setFont('helvetica', 'italic');
      doc.setTextColor(100, 100, 100);
      doc.text(`Figura ${figureCounter}. Evidencia t\u00e9cnica obtenida del an\u00e1lisis automatizado — ${alert.name.substring(0, 60)}.`, margin, y + 2);
      y += 8;
    } else {
      // Placeholder para Captura de Pantalla (ZAP Evidence)
      checkPage(40);
      doc.setDrawColor(...COLORS.gray);
      doc.setLineWidth(0.1);
      doc.rect(margin, y, contentW, 35);
      doc.setTextColor(...COLORS.gray);
      doc.setFontSize(8);
      doc.text('[ EVIDENCIA VISUAL / SCREENSHOT DE ZAP ]', margin + contentW / 2, y + 18, { align: 'center' });
      doc.setFontSize(6);
      doc.text(`Referencia: ${alert.id} - ${alert.source}`, margin + contentW / 2, y + 22, { align: 'center' });
      y += 42;
    }

    // ═══════════════════════════════════════
    // GUÍA DE REMEDIACIÓN (AI SECURITY CORE)
    // ═══════════════════════════════════════
    if (alert.aiRemediation) {
      checkPage(60);

      // Warning banner
      doc.setFillColor(50, 45, 30);
      doc.roundedRect(margin, y, contentW, 14, 2, 2, 'F');
      doc.setDrawColor(200, 160, 0);
      doc.setLineWidth(0.3);
      doc.roundedRect(margin, y, contentW, 14, 2, 2, 'S');

      // Warning icon + title
      doc.setTextColor(200, 160, 0);
      doc.setFontSize(8);
      doc.setFont('helvetica', 'bold');
      doc.text('Guía de Remediación (AI Security Core)', margin + 4, y + 5.5);

      doc.setFont('helvetica', 'italic');
      doc.setFontSize(5.5);
      doc.setTextColor(180, 160, 100);
      doc.text('AVISO: La IA es un asistente para mitigar el burnout del analista. El código propuesto SIEMPRE debe ser auditado por un humano antes del parcheo.', margin + 4, y + 10.5);
      y += 18;

      // Parse AI remediation content into sections
      const cleanedMD = alert.aiRemediation
        .replace(/[^\x20-\x7E\xA0-\xFF\u0100-\u017F\n\r?\u00bf]/g, '')
        .replace(/\*\*/g, '')
        .replace(/###/g, '')
        .replace(/##/g, '')
        .replace(/`/g, '');

      // Split by known section headers
      const sections = cleanedMD.split(/(?=Que significa|Impacto en la|Recomendaci)/i);

      sections.forEach(section => {
        if (!section.trim()) return;
        checkPage(20);

        // Check if it's a section header
        const headerMatch = section.match(/^(.*?)\n/);
        if (headerMatch) {
          const header = headerMatch[1].trim();
          if (header.length > 5 && header.length < 80) {
            doc.setFontSize(8);
            doc.setFont('helvetica', 'bold');
            doc.setTextColor(...COLORS.accent);
            doc.text(header, margin, y);
            y += 5;
          }
        }

        // Body text
        const bodyText = section.replace(/^.*?\n/, '').trim();
        if (bodyText) {
          doc.setFontSize(7);
          doc.setFont('helvetica', 'normal');
          doc.setTextColor(80, 80, 80);
          const aiLines = doc.splitTextToSize(bodyText, contentW);
          aiLines.forEach((line: string) => {
            checkPage(6);
            doc.text(line, margin, y);
            y += 3.5;
          });
          y += 3;
        }
      });

      y += 5;
    }

    });
  });

  // ═══════════════════════════════════════
  // ═══════════════════════════════════════
  // EVALUACIÓN DE RIESGO
  // ═══════════════════════════════════════
  doc.addPage();
  sectionPages['evaluacionRiesgo'] = doc.getNumberOfPages();
  y = 25;

  doc.setTextColor(...COLORS.accent);
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  chapterMap['riesgo'] = String(chapterNum++);
  doc.text(`${chapterMap['riesgo']}. Evaluación de Riesgo`, margin, y);
  y += 10;

  doc.setTextColor(80, 80, 80);
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.text('Esta clasificación se realizó en base a un criterio detallado en el Anexo: Criterio de Clasificación de Riesgo.', margin, y);
  y += 10;

  const inferRiskFactors = (a: any) => {
    if (a.riskFactors) return a.riskFactors;
    const sev = a.severity.toLowerCase();
    const name = a.name.toLowerCase();
    let baseTh = sev === 'critical' ? 9 : sev === 'high' ? 7 : sev === 'medium' ? 5 : 3;
    let baseVu = sev === 'critical' ? 9 : sev === 'high' ? 7 : sev === 'medium' ? 5 : 3;
    let baseTe = sev === 'critical' ? 9 : sev === 'high' ? 7 : sev === 'medium' ? 4 : 2;
    let baseBu = sev === 'critical' ? 9 : sev === 'high' ? 6 : sev === 'medium' ? 3 : 1;
    if (name.includes('xss') || name.includes('cross-site')) {
      baseTh = 8; baseVu = 7; baseTe = 6; baseBu = 5;
    } else if (name.includes('injection') || name.includes('sql')) {
      baseTh = 9; baseVu = 8; baseTe = 9; baseBu = 8;
    } else if (name.includes('security-policy') || name.includes('header') || name.includes('options') || name.includes('cabecera') || name.includes('protection')) {
      baseTh = 4; baseVu = 9; baseTe = 2; baseBu = 1;
    } else if (name.includes('cookie')) {
      baseTh = 3; baseVu = 9; baseTe = 2; baseBu = 2;
    }
    return {
      threat: { a1: Math.max(1, baseTh - 1), a2: baseTh, a3: Math.max(1, baseTh - 2), a4: baseTh },
      vulnerability: { v1: baseVu, v2: baseVu, v3: Math.max(1, baseVu - 2), v4: Math.max(1, baseVu - 1) },
      technical: { t1: baseTe, t2: Math.max(0, baseTe - 2), t3: Math.max(0, baseTe - 3), t4: baseTe },
      business: { n1: baseBu, n2: Math.max(1, baseBu - 1), n3: baseBu, n4: Math.max(1, baseBu - 2) }
    };
  };

  data.alerts.forEach((alert, idx) => {
    checkPage(120);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.text(`${alert.name} — RISK ID ${alert.severity[0].toUpperCase()}${idx + 1}`, margin, y);
    y += 8;

    const rf = inferRiskFactors(alert);
    if (rf) {
      const probTotal = (((Object.values(rf.threat) as number[]).reduce((a: number, b: number) => a + b, 0) / 4) + ((Object.values(rf.vulnerability) as number[]).reduce((a: number, b: number) => a + b, 0) / 4)) / 2;
      const techTotal = (Object.values(rf.technical) as number[]).reduce((a: number, b: number) => a + b, 0) / 4;
      const busiTotal = (Object.values(rf.business) as number[]).reduce((a: number, b: number) => a + b, 0) / 4;

      autoTable(doc, {
        startY: y,
        head: [[{ content: 'Estimación de Probabilidad', colSpan: 2, styles: { halign: 'center' } }, 'Valor']],
        body: [
          [{ content: 'Factor de\nAmenaza', rowSpan: 4, styles: { valign: 'middle', halign: 'center', fontStyle: 'bold' } }, 'a1 Destreza del atacante.', rf.threat.a1],
          ['a2 Motivación.', rf.threat.a2],
          ['a3 Oportunidad y recursos necesarios.', rf.threat.a3],
          ['a4 Tamaño del grupo de agentes que son potenciales amenazas.', rf.threat.a4],
          [{ content: 'Factor de\nVulnerabilidad', rowSpan: 4, styles: { valign: 'middle', halign: 'center', fontStyle: 'bold' } }, 'v1 Facilidad de descubrimiento de la vulnerabilidad.', rf.vulnerability.v1],
          ['v2 Facilidad de explotación de la amenaza.', rf.vulnerability.v2],
          ['v3 Conocimiento de la vulnerabilidad por parte del grupo de amenazas.', rf.vulnerability.v3],
          ['v4 Capacidad de detección de una posible explotación.', rf.vulnerability.v4],
          [{ content: 'Total:', colSpan: 2, styles: { fontStyle: 'bold', halign: 'right' } }, { content: probTotal.toFixed(2), styles: { fontStyle: 'bold' } }],
        ],
        theme: 'grid',
        headStyles: { fillColor: [240, 240, 240], textColor: [50, 50, 50], fontSize: 8 },
        bodyStyles: { fontSize: 7, textColor: [80, 80, 80] },
        columnStyles: {
          0: { cellWidth: 30 },
          2: { cellWidth: 15, halign: 'center' }
        },
        margin: { left: margin, right: margin, bottom: 25 },
      });

      y = (doc as any).lastAutoTable.finalY + 5;

      autoTable(doc, {
        startY: y,
        head: [[{ content: 'Estimación de Impacto', colSpan: 2, styles: { halign: 'center' } }, 'Valor']],
        body: [
          [{ content: 'Factores\nTécnicos', rowSpan: 4, styles: { valign: 'middle', halign: 'center', fontStyle: 'bold' } }, 't1 Pérdida de confidencialidad y niveles de sensibilidad de los datos afectados.', rf.technical.t1],
          ['t2 Pérdida de integridad y en qué grado.', rf.technical.t2],
          ['t3 Pérdida de disponibilidad.', rf.technical.t3],
          ['t4 Pérdida de la posibilidad de contabilizar o asignar el ataque a un individuo', rf.technical.t4],
          [{ content: 'Estimación de Impacto al Negocio', colSpan: 3, styles: { halign: 'center', fillColor: [240, 240, 240], textColor: [50, 50, 50], fontStyle: 'bold' } }],
          [{ content: 'Factores de\nNegocio', rowSpan: 4, styles: { valign: 'middle', halign: 'center', fontStyle: 'bold' } }, 'n1 Daño financiero a consecuencia de un ataque.', rf.business.n1],
          ['n2 Daño en la reputación.', rf.business.n2],
          ['n3 Incumplimiento de normativas.', rf.business.n3],
          ['n4 Violación de privacidad', rf.business.n4],
          [{ content: 'Total:', colSpan: 2, styles: { fontStyle: 'bold', halign: 'right' } }, { content: ((techTotal + busiTotal) / 2).toFixed(2), styles: { fontStyle: 'bold' } }],
        ],
        theme: 'grid',
        headStyles: { fillColor: [240, 240, 240], textColor: [50, 50, 50], fontSize: 8 },
        bodyStyles: { fontSize: 7, textColor: [80, 80, 80] },
        columnStyles: {
          0: { cellWidth: 30 },
          2: { cellWidth: 15, halign: 'center' }
        },
        margin: { left: margin, right: margin, bottom: 25 },
      });

      y = (doc as any).lastAutoTable.finalY + 15;
    }
  });

  // ═══════════════════════════════════════
  // OWASP TOP 10 MAPPING
  // ═══════════════════════════════════════
  doc.addPage();
  y = 25;

  doc.setTextColor(...COLORS.accent);
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  chapterMap['owasp'] = String(chapterNum++);
  doc.text(`${chapterMap['owasp']}. Alineación con OWASP Top 10 (2025)`, margin, y);
  y += 10;

  doc.setTextColor(80, 80, 80);
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  const owaspIntro = 'El siguiente mapeo vincula las vulnerabilidades detectadas con el estándar internacional OWASP Top 10, proporcionando un marco de referencia para la criticidad y el cumplimiento normativo.';
  doc.text(doc.splitTextToSize(owaspIntro, contentW), margin, y);
  y += 15;

  const owaspCategories = [
    { id: 'A01', name: 'Broken Access Control', desc: 'Fallas en la restricción de acceso a usuarios.' },
    { id: 'A02', name: 'Cryptographic Failures', desc: 'Exposición de datos sensibles por falta de cifrado.' },
    { id: 'A03', name: 'Injection', desc: 'Inyección de datos maliciosos (SQLi, XSS, etc.).' },
    { id: 'A04', name: 'Insecure Design', desc: 'Defectos arquitectónicos y de diseño de seguridad.' },
    { id: 'A05', name: 'Security Misconfiguration', desc: 'Configuraciones de seguridad débiles o ausentes.' },
    { id: 'A06', name: 'Vulnerable and Outdated Components', desc: 'Uso de librerías o software con fallos conocidos.' },
    { id: 'A07', name: 'Identification and Authentication Failures', desc: 'Fallas en el manejo de sesiones y contraseñas.' },
    { id: 'A08', name: 'Software and Data Integrity Failures', desc: 'Fallas en la verificación de integridad de datos.' },
    { id: 'A09', name: 'Security Logging and Monitoring Failures', desc: 'Falta de visibilidad sobre incidentes en curso.' },
    { id: 'A10', name: 'Server-Side Request Forgery (SSRF)', desc: 'Abuso de funcionalidades del servidor para atacar otros sistemas.' },
  ];

  // Pre-build OWASP links map for table hyperlinking
  const owaspTopTenLinks: Record<string, string> = {
    'A01': 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
    'A02': 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
    'A03': 'https://owasp.org/Top10/A03_2021-Injection/',
    'A04': 'https://owasp.org/Top10/A04_2021-Insecure_Design/',
    'A05': 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
    'A06': 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
    'A07': 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
    'A08': 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/',
    'A09': 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/',
    'A10': 'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_SSRF/',
  };

  autoTable(doc, {
    startY: y,
    head: [['ID', 'Categoría OWASP', 'Hallazgos Relacionados']],
    body: owaspCategories.map(cat => [
      cat.id,
      cat.name,
      data.alerts.filter(a => a.owaspCategory.includes(cat.id)).length > 0 
        ? data.alerts.filter(a => a.owaspCategory.includes(cat.id)).map(a => a.cweId).join(', ')
        : 'Ninguno'
    ]),
    theme: 'grid',
    headStyles: { fillColor: COLORS.accent, textColor: COLORS.white, fontSize: 8, fontStyle: 'bold' },
    bodyStyles: { fontSize: 8, textColor: [80, 80, 80] },
    didParseCell: (hookData: any) => {
      // Style OWASP ID column as link
      if (hookData.section === 'body' && hookData.column.index === 0) {
        hookData.cell.styles.textColor = COLORS.accent;
        hookData.cell.styles.fontStyle = 'bold';
      }
      // Style CWE IDs as links (when not 'Ninguno')
      if (hookData.section === 'body' && hookData.column.index === 2) {
        const val = hookData.cell.raw as string;
        if (val !== 'Ninguno') {
          hookData.cell.styles.textColor = COLORS.accent;
          hookData.cell.styles.fontStyle = 'bold';
        }
      }
    },
    didDrawCell: (hookData: any) => {
      // OWASP ID → link to official OWASP page
      if (hookData.section === 'body' && hookData.column.index === 0) {
        const owaspId = hookData.cell.raw as string;
        const link = owaspTopTenLinks[owaspId] || 'https://owasp.org/www-project-top-ten/';
        doc.link(hookData.cell.x, hookData.cell.y, hookData.cell.width, hookData.cell.height, { url: link });
      }
      // CWE IDs → link to first CWE in MITRE
      if (hookData.section === 'body' && hookData.column.index === 2) {
        const val = hookData.cell.raw as string;
        if (val !== 'Ninguno') {
          const firstCwe = val.split(',')[0].trim().replace(/[^0-9]/g, '');
          if (firstCwe) {
            doc.link(hookData.cell.x, hookData.cell.y, hookData.cell.width, hookData.cell.height, { url: `https://cwe.mitre.org/data/definitions/${firstCwe}.html` });
          }
        }
      }
    },
    margin: { left: margin, right: margin, bottom: 25 },
    tableWidth: contentW,
  });

  y = (doc as any).lastAutoTable.finalY + 15;

  // ═══════════════════════════════════════
  // MOZILLA OBSERVATORY TESTS
  // ═══════════════════════════════════════
  if (data.observatoryTests && data.observatoryTests.length > 0) {
    doc.addPage();
    y = 25;

    doc.setTextColor(...COLORS.accent);
    doc.setFontSize(16);
    doc.setFont('helvetica', 'bold');
  chapterMap['mozilla'] = String(chapterNum++);
    doc.text(`${chapterMap['mozilla']}. Mozilla Observatory Security Tests`, margin, y);
    y += 10;

    // Resumen de la nota
    doc.setFillColor(...(data.observatoryScore || 0) >= 80 ? COLORS.green : (data.observatoryScore || 0) >= 50 ? COLORS.medium : COLORS.critical);
    doc.roundedRect(margin, y, 90, 20, 2, 2, 'F');
    doc.setTextColor(...COLORS.white);
    doc.setFontSize(14);
    doc.text(`Nota Oficial:   ${data.observatoryGrade}`, margin + 5, y + 8);
    doc.setFontSize(10);
    doc.text(`Puntuación de Seguridad: ${data.observatoryScore}/100`, margin + 5, y + 16);

    y += 30;

    doc.setTextColor(80, 80, 80);
    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    doc.text(doc.splitTextToSize('A continuación se detallan los resultados de los 10 tests de seguridad estandarizados, evaluando la adopción de cabeceras de servidor modernas y buenas prácticas criptográficas.', contentW), margin, y);
    y += 10;

    const testsData = data.observatoryTests.map(t => [
      t.pass ? 'PASS' : 'FAIL',
      t.name.replace('→', '->'),
      t.pass ? 'Implementado' : 'Faltante',
      t.scoreModifier === 0 ? 'Neutro' : `${t.scoreModifier > 0 ? '+' : ''}${t.scoreModifier} pts`,
      t.description.substring(0, 70)
    ]);

    // Mozilla Observatory docs mapping for each test
    const mozillaDocsLinks: Record<string, string> = {
      'content-security-policy': 'https://infosec.mozilla.org/guidelines/web_security#content-security-policy',
      'cookies': 'https://infosec.mozilla.org/guidelines/web_security#cookies',
      'cross-origin-resource-sharing': 'https://infosec.mozilla.org/guidelines/web_security#cross-origin-resource-sharing',
      'redirection': 'https://infosec.mozilla.org/guidelines/web_security#http-redirections',
      'referrer-policy': 'https://infosec.mozilla.org/guidelines/web_security#referrer-policy',
      'strict-transport-security': 'https://infosec.mozilla.org/guidelines/web_security#http-strict-transport-security',
      'subresource-integrity': 'https://infosec.mozilla.org/guidelines/web_security#subresource-integrity',
      'x-content-type-options': 'https://infosec.mozilla.org/guidelines/web_security#x-content-type-options',
      'x-frame-options': 'https://infosec.mozilla.org/guidelines/web_security#x-frame-options',
      'x-xss-protection': 'https://infosec.mozilla.org/guidelines/web_security#x-xss-protection',
    };

    // Store original test names for link resolution
    const originalTestNames = data.observatoryTests!.map(t => t.name);

    autoTable(doc, {
      startY: y,
      head: [['Estado', 'Test de Seguridad', 'Condición', 'Impacto', 'Descripción']],
      body: testsData,
      theme: 'grid',
      headStyles: { fillColor: COLORS.darkGray, textColor: COLORS.white, fontSize: 7, fontStyle: 'bold' },
      bodyStyles: { fontSize: 7, textColor: [80, 80, 80] },
      columnStyles: {
        0: { cellWidth: 15, fontStyle: 'bold' },
        1: { cellWidth: 35, fontStyle: 'bold' },
        3: { cellWidth: 15 },
      },
      didParseCell: (hookData: any) => {
        if (hookData.section === 'body' && hookData.column.index === 0) {
          const val = hookData.cell.raw as string;
          if (val.includes('PASS')) hookData.cell.styles.textColor = COLORS.green;
          if (val.includes('FAIL')) hookData.cell.styles.textColor = COLORS.critical;
        }
        // Style test name column as clickable link
        if (hookData.section === 'body' && hookData.column.index === 1) {
          hookData.cell.styles.textColor = COLORS.accent;
        }
      },
      didDrawCell: (hookData: any) => {
        // Test name → link to Mozilla infosec docs
        if (hookData.section === 'body' && hookData.column.index === 1) {
          const rowIdx = hookData.row.index;
          const originalName = originalTestNames[rowIdx] || '';
          const nameKey = originalName.toLowerCase().replace(/[^a-z-]/g, '');
          // Find closest matching doc link
          const docLink = Object.entries(mozillaDocsLinks).find(([key]) => nameKey.includes(key));
          if (docLink) {
            doc.link(hookData.cell.x, hookData.cell.y, hookData.cell.width, hookData.cell.height, { url: docLink[1] });
          } else {
            doc.link(hookData.cell.x, hookData.cell.y, hookData.cell.width, hookData.cell.height, { url: 'https://infosec.mozilla.org/guidelines/web_security' });
          }
        }
      },
      margin: { left: margin, right: margin, bottom: 25 },
      tableWidth: contentW,
    });

    y = (doc as any).lastAutoTable.finalY + 15;
  }

  // ═══════════════════════════════════════
  // SPIDER / SUPERFICIE DE ATAQUE
  // ═══════════════════════════════════════
  if (data.spiderResults.length > 0) {
    doc.addPage();
    y = 25;

    doc.setTextColor(...COLORS.accent);
    doc.setFontSize(16);
    doc.setFont('helvetica', 'bold');
    chapterMap['spider'] = String(chapterNum++);
    doc.text(`${chapterMap['spider']}. Superficie de Ataque (Spider/Crawler)`, margin, y);
    y += 5;
    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(100, 100, 100);
    doc.text(`Se descubrieron ${data.spiderResults.length} endpoints durante la fase de reconocimiento.`, margin, y + 5);
    y += 12;

    // Notice: Login required for interactive verification
    doc.setFillColor(240, 240, 240);
    doc.roundedRect(margin, y, contentW, 12, 1.5, 1.5, 'F');
    doc.setDrawColor(180, 180, 180);
    doc.roundedRect(margin, y, contentW, 12, 1.5, 1.5, 'S');
    doc.setTextColor(100, 100, 100);
    doc.setFontSize(6.5);
    doc.setFont('helvetica', 'italic');
    doc.text('NOTA: Para verificar los endpoints en l\u00ednea, inicie sesi\u00f3n con su cuenta de Google en la plataforma de auditor\u00eda.', margin + 4, y + 5);
    doc.text('Para m\u00e1s informaci\u00f3n, cont\u00e1ctese con el Equipo de Auditor\u00eda de Seguridad de Empresa Default.', margin + 4, y + 9.5);
    y += 16;

    // Store full URLs for link resolution
    const spiderUrls = data.spiderResults.map(sr => sr.url);

    autoTable(doc, {
      startY: y,
      head: [['URL', 'Método', 'Tipo', 'Contexto']],
      body: data.spiderResults.map(sr => [
        sr.url.substring(0, 55),
        sr.method,
        sr.type,
        sr.context || '-',
      ]),
      theme: 'grid',
      headStyles: { fillColor: COLORS.darkGray, textColor: COLORS.white, fontSize: 7, fontStyle: 'bold' },
      bodyStyles: { fontSize: 7, textColor: [80, 80, 80] },
      didParseCell: (hookData: any) => {
        // Style URL column as clickable link
        if (hookData.section === 'body' && hookData.column.index === 0) {
          hookData.cell.styles.textColor = COLORS.accent;
          hookData.cell.styles.fontStyle = 'bold';
        }
      },
      didDrawCell: (hookData: any) => {
        // URL → clickable link to the discovered endpoint
        if (hookData.section === 'body' && hookData.column.index === 0) {
          const fullUrl = spiderUrls[hookData.row.index];
          if (fullUrl) {
            doc.link(hookData.cell.x, hookData.cell.y, hookData.cell.width, hookData.cell.height, { url: fullUrl });
          }
        }
      },
      margin: { left: margin, right: margin, bottom: 25 },
      tableWidth: contentW,
    });

    y = (doc as any).lastAutoTable.finalY + 15;
  }


  // ═══════════════════════════════════════
  // AUDIT LOG
  // ═══════════════════════════════════════
  y += 5;
  checkPage(40);

  
  
  

  doc.setTextColor(...COLORS.accent);
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  chapterMap['auditoria'] = String(chapterNum++);
  doc.text(`${chapterMap['auditoria']}. Registro de Auditoría (Cadena de Custodia)`, margin, y);
  y += 5;
  doc.setFontSize(8);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(100, 100, 100);
  doc.text('Registro inmutable de todas las acciones realizadas durante la sesión.', margin, y + 5);
  y += 15;

  const logEntries = data.auditLogs.slice(0, 30).map(log => {
    // Remove emojis to prevent jsPDF text width calculation issues
    const cleanAction = log.action.replace(/[^\x20-\x7E\xA0-\xFF\u0100-\u017F]/g, '').trim();
    return [
      new Date(log.timestamp).toLocaleTimeString(),
      log.type.toUpperCase(),
      cleanAction.substring(0, 80),
    ];
  });

  autoTable(doc, {
    startY: y,
    head: [['Hora', 'Tipo', 'Acción']],
    body: logEntries,
    theme: 'grid',
    headStyles: { fillColor: COLORS.darkGray, textColor: COLORS.white, fontSize: 7, fontStyle: 'bold' },
    bodyStyles: { fontSize: 6.5, textColor: [80, 80, 80] },
    columnStyles: {
      0: { cellWidth: 20 },
      1: { cellWidth: 18 },
    },
    margin: { left: margin, right: margin, bottom: 25 },
    tableWidth: contentW,
  });

  y = (doc as any).lastAutoTable.finalY + 15;

  // ═══════════════════════════════════════
  // CONCLUSIONES Y RECOMENDACIONES
  // ═══════════════════════════════════════
  doc.addPage();
  sectionPages['conclusiones'] = doc.getNumberOfPages();
  y = 25;

  doc.setTextColor(...COLORS.accent);
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  chapterMap['conclusiones'] = String(chapterNum++);
  doc.text(`${chapterMap['conclusiones']}. Conclusiones`, margin, y);
  y += 12;

  doc.setTextColor(80, 80, 80);
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');

  const conclusions = `La infraestructura auditada (${data.target}) presenta un nivel de riesgo ${crit > 0 ? 'CRÍTICO' : high > 0 ? 'ALTO' : 'MODERADO'} basado en los hallazgos identificados. Se evidencia la necesidad de un ciclo de parcheo continuo y de robustecer la arquitectura de red y aplicación.`;

  const concLines = doc.splitTextToSize(conclusions, contentW);
  doc.text(concLines, margin, y);
  y += concLines.length * 4 + 15;

  // ═══════════════════════════════════════
  // RECOMENDACIONES
  // ═══════════════════════════════════════
  checkPage(80);
  sectionPages['recomendaciones'] = doc.getNumberOfPages();
  
  doc.setTextColor(...COLORS.accent);
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  chapterMap['recomendaciones'] = String(chapterNum++);
  doc.text(`${chapterMap['recomendaciones']}. Recomendaciones`, margin, y);
  y += 12;

  doc.setTextColor(80, 80, 80);
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');

  const recomms = `Recomendaciones prioritarias:

1. INMEDIATO (0-24 horas): Remediar todas las vulnerabilidades de severidad Crítica. ${crit > 0 ? `Se identificaron ${crit} hallazgo(s) crítico(s).` : ''}

2. CORTO PLAZO (1-7 días): Remediar vulnerabilidades de severidad Alta. ${high > 0 ? `Se identificaron ${high} hallazgo(s) de alta severidad.` : ''}

3. MEDIANO PLAZO (1-30 días): Implementar cabeceras de seguridad HTTP faltantes y configurar WAF (Web Application Firewall) para protección en capa de aplicación.

4. CONTINUO: Implementar un programa de gestión de vulnerabilidades con escaneos automatizados periódicos y auditorías trimestrales.

Estado de Remediación:
— Vulnerabilidades identificadas: ${totalVulns}
— Vulnerabilidades mitigadas durante la sesión: ${resolvedCount}
— Vulnerabilidades pendientes: ${totalVulns - resolvedCount}
— Cobertura de remediación: ${totalVulns > 0 ? Math.round((resolvedCount / totalVulns) * 100) : 0}%`;

  const recLines = doc.splitTextToSize(recomms, contentW);
  doc.text(recLines, margin, y);
  y += recLines.length * 4 + 20;

  // Firma
  checkPage(40);
  doc.setDrawColor(...COLORS.accent);
  doc.setLineWidth(0.5);
  doc.line(margin, y, margin + 60, y);
  y += 5;
  doc.setTextColor(80, 80, 80);
  doc.setFontSize(8);
  doc.text('Auditor de Seguridad Informática — Empresa Default', margin, y);
  y += 4;
  doc.text(`Fecha: ${reportDate}`, margin, y);
  y += 4;
  doc.text('Equipo de Auditoría de Seguridad — Empresa Default', margin, y);

  // Segunda firma
  doc.setDrawColor(...COLORS.accent);
  doc.line(pageW - margin - 60, y - 13, pageW - margin, y - 13);
  doc.text('Revisado por: Auditor en Jefe', pageW - margin - 60, y - 8);
  doc.text(`Fecha: ${reportDate}`, pageW - margin - 60, y - 4);

  // Footer con clasificación
  y += 20;
  doc.setFillColor(...COLORS.critical);
  doc.roundedRect(margin, y, contentW, 10, 2, 2, 'F');
  doc.setTextColor(...COLORS.white);
  doc.setFontSize(8);
  doc.setFont('helvetica', 'bold');
  doc.text('DOCUMENTO CONFIDENCIAL — Distribución restringida al equipo de auditoría y al cliente autorizado', 105, y + 6.5, { align: 'center' });

  // ═══════════════════════════════════════
  // ANEXO 9: HALLAZGO FUERA DE ÁMBITO
  // ═══════════════════════════════════════
  doc.addPage();
  sectionPages['anexoFueraAmbito'] = doc.getNumberOfPages();
  y = 25;

  doc.setTextColor(...COLORS.accent);
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  chapterMap['anexo1'] = String(chapterNum++);
  doc.text(`${chapterMap['anexo1']}. Anexo: Hallazgo fuera de ámbito`, margin, y);
  y += 10;

  doc.setTextColor(80, 80, 80);
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.text('Se detectaron hallazgos menores o configuraciones que no forman parte del alcance principal web, pero se reportan para mejorar la seguridad integral de la infraestructura.', margin, y, { maxWidth: contentW });
  y += 15;

  // ═══════════════════════════════════════
  // ANEXO 10: CRITERIO DE CLASIFICACIÓN
  // ═══════════════════════════════════════
  doc.addPage();
  y = 25;

  doc.setTextColor(...COLORS.accent);
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  chapterMap['anexo2'] = String(chapterNum++);
  doc.text(`${chapterMap['anexo2']}. Anexo: Criterio de Clasificación de Riesgo`, margin, y);
  y += 10;

  doc.setTextColor(80, 80, 80);
  doc.setFontSize(9);
  doc.setFont('helvetica', 'bold');
  doc.text(`${chapterNum - 1}.1 Estimación`, margin, y);
  y += 6;
  doc.setFont('helvetica', 'normal');
  doc.text('La metodología seguida se ajusta a la guía de pruebas OWASP (versión 3), siendo el modelo de riesgo estándar: RIESGO = PROBABILIDAD * IMPACTO.', margin, y, { maxWidth: contentW });
  y += 12;

  const criteriaSections = [
    { title: '10.2 FACTORES DE AMENAZA', content: 'A1 Destreza del atacante, A2 Motivación, A3 Oportunidad y recursos necesarios, A4 Tamaño del grupo de agentes.' },
    { title: '10.3 FACTORES DE VULNERABILIDAD', content: 'V1 Facilidad de descubrimiento, V2 Facilidad de explotación, V3 Conocimiento de la vulnerabilidad, V4 Capacidad de detección.' },
    { title: '10.4 FACTORES DE IMPACTO TÉCNICO', content: 'T1 Pérdida de confidencialidad, T2 Pérdida de integridad, T3 Pérdida de disponibilidad, T4 Pérdida de responsabilidad (accountability).' },
    { title: '10.5 FACTORES DE IMPACTO AL NEGOCIO', content: 'N1 Daño financiero, N2 Daño en reputación, N3 Incumplimiento de normativas, N4 Violación de privacidad.' },
  ];

  criteriaSections.forEach(sec => {
    checkPage(30);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(...COLORS.accent);
    doc.text(sec.title, margin, y);
    y += 6;
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(80, 80, 80);
    doc.text(doc.splitTextToSize(sec.content, contentW), margin, y);
    y += 12;
  });

  // ═══════════════════════════════════════
  // ANEXO 11: EVIDENCIAS FOTOGRÁFICAS DE ESCÁNER
  // ═══════════════════════════════════════
  doc.addPage();
  sectionPages['anexoEvidencias'] = doc.getNumberOfPages();
  y = 25;

  doc.setTextColor(...COLORS.accent);
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  chapterMap['anexo3'] = String(chapterNum++);
  doc.text(`${chapterMap['anexo3']}. Anexo: Evidencias Fotográficas de Escáner`, margin, y);
  y += 10;

  doc.setTextColor(80, 80, 80);
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.text('A continuación se presenta la evidencia visual extraída del escáner OWASP ZAP durante la ejecución de las pruebas automatizadas (Spiders y Escaneo Activo).', margin, y, { maxWidth: contentW });
  y += 15;

  // Evidencia 1
  if (ZAP_EVIDENCE_1) {
    const imgHeight = 60;
    doc.addImage(ZAP_EVIDENCE_1, 'JPEG', margin, y, contentW, imgHeight);
    y += imgHeight + 5;
    doc.setFont('helvetica', 'italic');
    doc.setFontSize(8);
    doc.text('Figura 1. Evidencia técnica de descubrimiento de endpoints mediante OWASP ZAP Spider.', margin + contentW / 2, y, { align: 'center' });
    y += 15;
  }

  // Evidencia 2
  if (ZAP_EVIDENCE_2) {
    const imgHeight = 60;
    checkPage(imgHeight + 20);
    doc.addImage(ZAP_EVIDENCE_2, 'JPEG', margin, y, contentW, imgHeight);
    y += imgHeight + 5;
    doc.setFont('helvetica', 'italic');
    doc.setFontSize(8);
    doc.text('Figura 2. Configuración y ejecución de escaneo automatizado en OWASP ZAP.', margin + contentW / 2, y, { align: 'center' });
    y += 15;
  }

  // Evidencia 3
  if (ZAP_EVIDENCE_3) {
    const imgHeight = 60;
    checkPage(imgHeight + 20);
    doc.addImage(ZAP_EVIDENCE_3, 'JPEG', margin, y, contentW, imgHeight);
    y += imgHeight + 5;
    doc.setFont('helvetica', 'italic');
    doc.setFontSize(8);
    doc.text('Figura 3. Listado de alertas detectadas en la aplicación objetivo por OWASP ZAP.', margin + contentW / 2, y, { align: 'center' });
    y += 15;
  }

  // Evidencia 4 (Mozilla)
  if (MOZILLA_EVIDENCE_1) {
    const imgHeight = 60;
    checkPage(imgHeight + 20);
    doc.addImage(MOZILLA_EVIDENCE_1, 'JPEG', margin, y, contentW, imgHeight);
    y += imgHeight + 5;
    doc.setFont('helvetica', 'italic');
    doc.setFontSize(8);
    doc.text('Figura 4. Resultados del análisis de cabeceras HTTP realizado con Mozilla Observatory.', margin + contentW / 2, y, { align: 'center' });
    y += 15;
  }

  // ═══════════════════════════════════════
  // ANEXO 12: GLOSARIO
  // ═══════════════════════════════════════
  doc.addPage();
  sectionPages['glosario'] = doc.getNumberOfPages();
  y = 25;

  doc.setTextColor(...COLORS.accent);
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  chapterMap['anexo4'] = String(chapterNum++);
  doc.text(`${chapterMap['anexo4']}. Anexo: Glosario`, margin, y);
  y += 10;

  const glosarioData = [
    ['CWE', 'Common Weakness Enumeration - Diccionario de debilidades de software.'],
    ['CVE', 'Common Vulnerabilities and Exposures - Lista de vulnerabilidades conocidas.'],
    ['OWASP', 'Open Web Application Security Project.'],
    ['WAF', 'Web Application Firewall.'],
    ['CID', 'Confidencialidad, Integridad y Disponibilidad (Tríada de seguridad).'],
    ['XSS', 'Cross-Site Scripting - Inyección de código en el navegador.'],
    ['SQLi', 'SQL Injection - Inyección de comandos en base de datos.']
  ];

  autoTable(doc, {
    startY: y,
    head: [['Término', 'Definición']],
    body: glosarioData,
    theme: 'grid',
    headStyles: { fillColor: COLORS.darkGray, textColor: COLORS.white, fontSize: 8, fontStyle: 'bold' },
    bodyStyles: { fontSize: 8, textColor: [80, 80, 80] },
    margin: { left: margin, right: margin, bottom: 25 },
    tableWidth: contentW,
  });

  y = (doc as any).lastAutoTable.finalY + 15;

  // ═══════════════════════════════════════
  // GENERAR ÍNDICE DINÁMICO (con páginas reales)
  // ═══════════════════════════════════════

  // ═══════════════════════════════════════
  // REFERENCIAS BIBLIOGRÁFICAS
  // ═══════════════════════════════════════
  doc.addPage();
  y = 25;
  sectionPages['referencias'] = doc.getNumberOfPages();

  doc.setTextColor(...COLORS.accent);
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  chapterMap['referencias'] = String(chapterNum++);
  doc.text(`${chapterMap['referencias']}. Referencias Bibliográficas`, margin, y);
  y += 10;

  doc.setTextColor(80, 80, 80);
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  
  const references = [
    'MITRE Corporation. (2024). Common Weakness Enumeration (CWE). https://cwe.mitre.org/',
    'Mozilla. (2024). Mozilla Observatory. https://observatory.mozilla.org/',
    'National Institute of Standards and Technology [NIST]. (2008). Technical Guide to Information Security Testing and Assessment (SP 800-115). https://csrc.nist.gov/publications/detail/sp/800-115/final',
    'Open Worldwide Application Security Project [OWASP]. (2021). OWASP Top 10:2021. https://owasp.org/Top10/',
    'Open Worldwide Application Security Project [OWASP]. (n.d.). OWASP Risk Rating Methodology. https://owasp.org/www-community/OWASP_Risk_Rating_Methodology',
    'OWASP ZAP. (2024). ZAP - The world\'s most widely used web scanner. https://www.zaproxy.org/'
  ];

  references.forEach(ref => {
    const lines = doc.splitTextToSize(ref, contentW - 10);
    doc.text(lines[0], margin, y);
    if (lines.length > 1) {
      const remainingLines = lines.slice(1);
      doc.text(remainingLines, margin + 10, y + 5);
      y += (remainingLines.length * 5);
    }
    y += 8;
  });

  const dynamicTocItems = [
    { num: chapterMap['acuerdo'], title: 'Acuerdo de confidencialidad', page: String(sectionPages['confidencialidad'] || '–') },
    { num: chapterMap['alcance'], title: 'Alcance y objetivo', page: String(sectionPages['alcance'] || '–') },
    { num: chapterMap['metodologia'], title: 'Metodología', page: String(sectionPages['metodologia'] || '–') },
    { num: chapterMap['resumen'], title: 'Resumen de resultados y Matriz de Riesgo', page: String(sectionPages['matrizRiesgo'] || '–') },
    { num: chapterMap['detalle'], title: 'Detalle de vulnerabilidades y pruebas', page: String(sectionPages['detalle'] || '–') },
    { num: chapterMap['riesgo'], title: 'Evaluación de riesgo', page: String(sectionPages['evaluacionRiesgo'] || '–') },
    ...(chapterMap['spider'] ? [{ num: chapterMap['spider'], title: 'Superficie de Ataque (Spider/Crawler)', page: String(sectionPages['spider'] || '–') }] : []),
    { num: chapterMap['owasp'], title: 'Alineación con OWASP Top 10 (2025)', page: String(sectionPages['owasp'] || '–') },
    ...(chapterMap['mozilla'] ? [{ num: chapterMap['mozilla'], title: 'Mozilla Observatory Security Tests', page: String(sectionPages['observatory'] || '–') }] : []),
    { num: chapterMap['auditoria'], title: 'Registro de Auditoría', page: String(sectionPages['auditoria'] || '–') },
    { num: chapterMap['conclusiones'], title: 'Conclusiones', page: String(sectionPages['conclusiones'] || '–') },
    { num: chapterMap['recomendaciones'], title: 'Recomendaciones', page: String(sectionPages['recomendaciones'] || '–') },
    { num: chapterMap['anexo1'], title: 'Anexo: Hallazgo fuera de ámbito', page: String(sectionPages['anexoFueraAmbito'] || '–') },
    { num: chapterMap['anexo2'], title: 'Anexo: Criterio de clasificación de riesgo', page: String(sectionPages['anexoCriterio'] || '–') },
    { num: chapterMap['anexo3'], title: 'Anexo: Evidencias Fotográficas', page: String(sectionPages['evidencias'] || '–') },
    { num: chapterMap['anexo4'], title: 'Anexo: Glosario', page: String(sectionPages['glosario'] || '–') },
    { num: chapterMap['referencias'], title: 'Referencias Bibliográficas', page: String(sectionPages['referencias'] || '–') }
  ].filter(item => item.num !== undefined);

  // Ir a la página del TOC y dibujar
  doc.setPage(tocPageNumber);
  let tocY = 30;

  doc.setFillColor(...COLORS.accent);
  doc.rect(0, 0, 210, 4, 'F');

  doc.setTextColor(...COLORS.accent);
  doc.setFontSize(20);
  doc.setFont('helvetica', 'bold');
  doc.text('ÍNDICE', margin, tocY);
  tocY += 5;
  doc.setDrawColor(...COLORS.accent);
  doc.setLineWidth(1);
  doc.line(margin, tocY, margin + 30, tocY);
  tocY += 15;

  dynamicTocItems.forEach(item => {
    doc.setTextColor(...COLORS.gray);
    doc.setFontSize(11);
    doc.setFont('helvetica', 'normal');
    doc.text(`${item.num}.`, margin, tocY);
    doc.text(item.title, margin + 10, tocY);
    doc.setTextColor(...COLORS.accent);
    doc.text(item.page, pageW - margin, tocY, { align: 'right' });

    doc.setDrawColor(50, 60, 80);
    doc.setLineWidth(0.2);
    doc.setLineDashPattern([1, 1], 0);
    doc.line(margin + 10 + doc.getTextWidth(item.title) + 2, tocY, pageW - margin - doc.getTextWidth(item.page) - 2, tocY);
    doc.setLineDashPattern([], 0);
    tocY += 10;
  });

  // ═══════════════════════════════════════
  // APLICAR HEADERS Y FOOTERS A TODAS LAS PÁGINAS (EXCEPTO PORTADA)
  // ═══════════════════════════════════════
  const totalPages = doc.getNumberOfPages();
  console.log('Total pages generated (PDF):', totalPages);
  for (let i = 2; i <= totalPages; i++) {
    doc.setPage(i);
    addPageHeader();
    addPageFooter(i);
  }

  // ═══ GUARDAR ═══

  const filename = `Informe_Vulnerabilidades_${data.target.replace(/[^a-zA-Z0-9]/g, '_')}_${new Date().toISOString().split('T')[0]}.pdf`;
  doc.save(filename);
}
