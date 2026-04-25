/* eslint-disable @typescript-eslint/no-explicit-any */
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import { logoBase64 } from '@/lib/logoBase64';
import { ZAP_EVIDENCE_1, ZAP_EVIDENCE_2, ZAP_EVIDENCE_3, MOZILLA_EVIDENCE_1 } from '@/lib/zapEvidence';
interface Alert {
  id: string;
  source: string;
  cweId: string;
  owaspCategory: string;
  name: string;
  severity: string;
  riskScore: number;
  affectedUrl: string;
  description: string;
  evidence: string;
  header?: string;
  recommendation?: string;
  aiRemediation?: string;
  nvdData?: any;
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

export function generateTechnicalReport(data: ReportData, pdfPassword: string): void {
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
  const pageW = 210;
  const margin = 20;
  const contentW = pageW - margin * 2;
  let y = 0;

  const reportDate = new Date().toLocaleDateString('es-ES', {
    year: 'numeric', month: 'long', day: 'numeric'
  });
  const resolvedCount = data.patchedAlerts.length;
  const totalVulns = data.alerts.length;
  const crit = data.scanSummary?.critical || 0;
  const high = data.scanSummary?.high || 0;

  const checkPage = (needed: number) => {
    if (y + needed > 275) {
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
    doc.text('Empresa Default — Informe Técnico de Remediación', margin, 9);
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
  if (logoBase64) {
    doc.addImage(logoBase64, 'JPEG', 150, 20, 40, 15);
  }

  // Título
  doc.setTextColor(...COLORS.primary);
  doc.setFontSize(24);
  doc.setFont('helvetica', 'bold');
  doc.text('TECHNICAL PLAYBOOK:', margin, 100);
  doc.text('GUÍA DE REMEDIACIÓN', margin, 112);

  // Subtítulo
  doc.setFontSize(10);
  doc.setTextColor(...COLORS.gray);
  doc.setFont('helvetica', 'normal');
  doc.text('INTERNAL DOCUMENTATION — ESTÁNDAR OWASP v3', margin, 122);

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
  // PÁGINA 2: ÍNDICE (placeholder - se rellena al final)
  // ═══════════════════════════════════════
  doc.addPage();
  const tocPageNumber = doc.getNumberOfPages();

  const sectionPages: Record<string, number> = {};
  const chapterMap: Record<string, string> = {};
  let chapterNum = 1;

  // ═══════════════════════════════════════
  // PÁGINA 3: ACUERDO DE CONFIDENCIALIDAD
  // ═══════════════════════════════════════
  doc.addPage();
  y = 25;

  doc.setTextColor(...COLORS.accent);
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  chapterMap['acuerdo'] = String(chapterNum++); doc.text(`${chapterMap['acuerdo']}. Acuerdo de Confidencialidad`, margin, y);
  y += 10;

  doc.setTextColor(80, 80, 80);
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  const acuerdoText = `Este documento técnico contiene información crítica de remediación y vulnerabilidades explotables relacionadas con la infraestructura de ${data.target}. El acceso a este manual de parches está estrictamente restringido al equipo de TI y personal de ciberseguridad autorizado.

Queda estrictamente prohibida la reproducción, distribución o divulgación total o parcial de este playbook sin el consentimiento previo y por escrito de los responsables de seguridad de la Universidad Tecnológica de Chile Empresa Default. Toda la información aquí contenida debe ser tratada bajo el más alto nivel de reserva corporativa.

El mal uso de esta información técnica para fines distintos a la remediación de seguridad puede conllevar responsabilidades legales graves.`;

  const acuerdoLines = doc.splitTextToSize(acuerdoText, contentW);
  doc.text(acuerdoLines, margin, y);
  y += acuerdoLines.length * 4.5 + 15;

  // § 2 — Alcance y Objetivo Técnico
  doc.setTextColor(...COLORS.accent);
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  chapterMap['alcance'] = String(chapterNum++); doc.text(`${chapterMap['alcance']}. Alcance y Objetivo Técnico`, margin, y);
  y += 10;

  doc.setTextColor(80, 80, 80);
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  const alcanceText = `Este playbook técnico proporciona las guías de remediación exactas y el código fuente necesario para mitigar las vulnerabilidades detectadas en ${data.target}. Su objetivo es facilitar el proceso de parcheo al equipo de desarrollo y asegurar la correcta implementación de controles de seguridad.

Alcance Técnico:
• Fragmentos de código en Node.js/Next.js.
• Configuraciones de Hardening de servidores y cabeceras HTTP.
• Pasos de verificación post-remediación.`;

  const alcanceLines = doc.splitTextToSize(alcanceText, contentW);
  doc.text(alcanceLines, margin, y);
  y += alcanceLines.length * 4.5 + 15;

  // ═══════════════════════════════════════
  // PÁGINA: METODOLOGÍA Y HERRAMIENTAS
  // ═══════════════════════════════════════
  doc.addPage();
  y = 25;

  doc.setTextColor(...COLORS.accent);
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  chapterMap['metodologia'] = String(chapterNum++); doc.text(`${chapterMap['metodologia']}. Metodología y Herramientas`, margin, y);
  y += 10;

  doc.setTextColor(80, 80, 80);
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  const metoDesc = 'La evaluación se basa en una metodología de caja negra (Black Box) siguiendo los estándares de OWASP y PTES. Se han utilizado herramientas líderes en la industria para garantizar la detección exhaustiva de vulnerabilidades.';
  doc.text(doc.splitTextToSize(metoDesc, contentW), margin, y);
  y += 15;

  // Cuadro de Herramientas (Solo las utilizadas)
  const tools = [
    'OWASP ZAP (Zed Attack Proxy)',
    'Mozilla Observatory',
    'Nast API Security Cloud',
    'Llama 3 AI Security Core',
  ];

  doc.setFillColor(245, 247, 250);
  doc.roundedRect(margin, y, contentW, 45, 2, 2, 'F');
  doc.setTextColor(...COLORS.primary);
  doc.setFontSize(10);
  doc.setFont('helvetica', 'bold');
  doc.text('HERRAMIENTAS UTILIZADAS EN LA EVALUACIÓN', margin + contentW / 2, y + 8, { align: 'center' });

  y += 15;
  doc.setFontSize(8);
  doc.setFont('helvetica', 'normal');
  
  // Dibujar herramientas en 2 columnas
  tools.forEach((tool, i) => {
    const col = i % 2;
    const row = Math.floor(i / 2);
    const tx = margin + 10 + col * (contentW / 2);
    const ty = y + row * 8;
    doc.text(`• ${tool}`, tx, ty);
  });

  y += 35;

  // ═══════════════════════════════════════
  // RESUMEN DE RESULTADOS Y MATRIZ DE RIESGO
  // ═══════════════════════════════════════
  doc.addPage();
  y = 25;

  doc.setTextColor(...COLORS.accent);
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  chapterMap['resumen'] = String(chapterNum++); doc.text(`${chapterMap['resumen']}. Resumen de Resultados y Matriz de Riesgo`, margin, y);
  y += 10;

  doc.setTextColor(80, 80, 80);
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.text('Priorización técnica de remediación basada en el impacto crítico y la facilidad de explotación.', margin, y);
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
    
    // Dibujar los IDs en la celda
    const displayIds = ids.slice(0, 6).join(', ');
    doc.text(displayIds, cellX + cellW / 2, cellY + cellH / 2, { align: 'center', maxWidth: cellW - 4 });
  });

  y += gridH + 20;

  // ═══════════════════════════════════════
  // CLASIFICACIÓN POR TRÍADA CIA
  // ═══════════════════════════════════════
  checkPage(60);
  doc.setTextColor(...COLORS.accent);
  doc.setFontSize(14);
  doc.setFont('helvetica', 'bold');
  doc.text(`${chapterMap['resumen']}.1 Clasificación por Tríada de Seguridad (CIA)`, margin, y);
  y += 8;

  const ciaData = data.alerts.map((a, idx) => [
    `${a.severity[0].toUpperCase()}${idx + 1}`,
    a.name.substring(0, 50),
    a.cia?.confidentiality ? 'X' : '-',
    a.cia?.integrity ? 'X' : '-',
    a.cia?.availability ? 'X' : '-',
  ]);

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
    margin: { left: margin, right: margin },
    tableWidth: contentW,
  });

  y = (doc as any).lastAutoTable.finalY + 15;

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
    margin: { left: margin, right: margin },
    tableWidth: contentW,
  });

  y = (doc as any).lastAutoTable.finalY + 10;
  
  doc.setFontSize(7);
  doc.setTextColor(80, 80, 80);
  doc.text('RISK ID:', margin, y);
  doc.text('C: Confidencialidad, A: Disponibilidad, I: Integridad, OP: Oportunidad de Mejora', margin + 15, y);
  y += 5;
  doc.text('Esfuerzo de mitigación:', margin, y);
      y += 5;
      doc.text('Complejidad: Habilidades / Recursos necesarios | Costo: Horas hombre (HH) Involucradas', margin, y);
  y += 10;

  // ═══════════════════════════════════════
  // HALLAZGOS DETALLADOS
  // ═══════════════════════════════════════
  doc.addPage();
  y = 25;

  doc.setTextColor(...COLORS.accent);
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  chapterMap['detalle'] = String(chapterNum++); doc.text(`${chapterMap['detalle']}. Detalles de Vulnerabilidades y Mitigación Técnica`, margin, y);
  y += 12;

  data.alerts.forEach((alert, idx) => {
    checkPage(50);
    
    doc.setFillColor(...COLORS.primary);
    doc.rect(margin, y, contentW, 8, 'F');
    doc.setTextColor(...COLORS.white);
    doc.setFontSize(9);
    doc.setFont('helvetica', 'bold');
    doc.text(`${chapterMap['detalle']}.${idx + 1}  ${alert.name}`, margin + 3, y + 5.5);
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

    autoTable(doc, {
      startY: y,
      head: [['NOMENCLATURA', 'RESUMEN DE HALLAZGO']],
      body: [
        ['RECURSO AFECTADO', alert.affectedUrl],
        ['RISK ID', `${alert.severity[0].toUpperCase()}${idx + 1}`],
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
      didParseCell: (data) => {
        if (data.section === 'body' && data.column.index === 1 && data.row.index === 4) {
          data.cell.styles.textColor = COLORS.accent;
          data.cell.styles.fontStyle = 'bold';
        }
      },
      didDrawCell: (data) => {
        if (data.section === 'body' && data.column.index === 1 && data.row.index === 4) {
          doc.link(data.cell.x, data.cell.y, data.cell.width, data.cell.height, { url: clickableLink });
        }
      },
      margin: { left: margin, right: margin },
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
    y += riskLines.length * 4 + 10;

    if (alert.nvdData) {
      doc.setFillColor(235, 245, 255);
      doc.roundedRect(margin, y, contentW, 25, 1, 1, 'F');
      doc.setTextColor(...COLORS.accent);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8);
      doc.text(`INFORMACIÓN OFICIAL NVD (${alert.nvdData.cveId})`, margin + 3, y + 6);
      
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(30, 30, 30);
      doc.setFontSize(7);
      const nvdDesc = `Severidad: ${alert.nvdData.severity} (Score: ${alert.nvdData.baseScore}) | Vector: ${alert.nvdData.vectorString}`;
      doc.text(nvdDesc, margin + 3, y + 12);
      
      const nvdOfficialDesc = `Descripción NVD: ${alert.nvdData.description.substring(0, 200)}${alert.nvdData.description.length > 200 ? '...' : ''}`;
      const nvdLines = doc.splitTextToSize(nvdOfficialDesc, contentW - 10);
      doc.text(nvdLines, margin + 3, y + 18);
      y += 32;
    }

    if (alert.aiRemediation) {
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(...COLORS.accent);
      doc.text('Guía de Remediación (AI Security Core):', margin, y);
      y += 6;
      
      doc.setFont('helvetica', 'italic');
      doc.setFontSize(7);
      doc.setTextColor(180, 80, 0); // Warning Color
      const warningText = 'AVISO DE SUPERVISIÓN: La IA es un asistente diseñado para mitigar el burnout del analista. El código propuesto SIEMPRE debe ser auditado por un humano antes del parcheo.';
      doc.text(doc.splitTextToSize(warningText, contentW), margin, y);
      y += 6;

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8);
      doc.setTextColor(30, 30, 30);
      
      const cleanedMD = alert.aiRemediation
        .replace(/[^\x20-\x7E\xA0-\xFF\u0100-\u017F\n\r]/g, '') // Elimina emojis y caracteres que rompen jsPDF
        .replace(/\*\*/g, '')
        .replace(/###/g, '')
        .replace(/`/g, '');
        
      const aiLines = doc.splitTextToSize(cleanedMD, contentW);
      
      aiLines.forEach((line: string) => {
        checkPage(10);
        doc.text(line, margin, y);
        y += 4;
      });
    }

    y += 10;
  });

  // ═══════════════════════════════════════
  // EVALUACIÓN DE RIESGO
  // ═══════════════════════════════════════
  doc.addPage();
  y = 25;


  doc.setTextColor(...COLORS.accent);
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  sectionPages['evaluacionRiesgo'] = doc.getNumberOfPages();
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
    doc.setTextColor(40, 40, 40);
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
  chapterMap['owasp'] = String(chapterNum++); doc.text(`${chapterMap['owasp']}. Alineación con OWASP Top 10 (2025)`, margin, y);
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
    margin: { left: margin, right: margin },
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
    chapterMap['mozilla'] = String(chapterNum++); doc.text(`${chapterMap['mozilla']}. Mozilla Observatory Security Tests`, margin, y);
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
      },
      margin: { left: margin, right: margin },
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
    y += 15;

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
      margin: { left: margin, right: margin },
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
  chapterMap['auditoria'] = String(chapterNum++); doc.text(`${chapterMap['auditoria']}. Registro de Auditoría (Cadena de Custodia)`, margin, y);
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
    margin: { left: margin, right: margin },
    tableWidth: contentW,
  });

  y = (doc as any).lastAutoTable.finalY + 15;

  // ═══════════════════════════════════════
  // CONCLUSIONES
  // ═══════════════════════════════════════
  doc.addPage();
  y = 25;

  doc.setTextColor(...COLORS.accent);
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  chapterMap['conclusiones'] = String(chapterNum++); doc.text(`${chapterMap['conclusiones']}. Conclusiones y Recomendaciones`, margin, y);
  y += 12;

  doc.setTextColor(80, 80, 80);
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');

  const conclusions = `La infraestructura auditada (${data.target}) presenta un nivel de riesgo ${crit > 0 ? 'CRÍTICO' : high > 0 ? 'ALTO' : 'MODERADO'} basado en los hallazgos identificados.

Recomendaciones prioritarias:

1. INMEDIATO (0-24 horas): Remediar todas las vulnerabilidades de severidad Crítica. ${crit > 0 ? `Se identificaron ${crit} hallazgo(s) crítico(s) que permiten compromiso completo del sistema.` : 'No se encontraron vulnerabilidades críticas.'}

2. CORTO PLAZO (1-7 días): Remediar vulnerabilidades de severidad Alta. ${high > 0 ? `Se identificaron ${high} hallazgo(s) de alta severidad que exponen datos sensibles o funcionalidad crítica.` : ''}

3. MEDIANO PLAZO (1-30 días): Implementar cabeceras de seguridad HTTP faltantes y configurar WAF (Web Application Firewall) para protección en capa de aplicación.

4. CONTINUO: Implementar un programa de gestión de vulnerabilidades con escaneos automatizados periódicos y auditorías trimestrales.

Estado de Remediación:
— Vulnerabilidades identificadas: ${totalVulns}
— Vulnerabilidades mitigadas durante la sesión: ${resolvedCount}
— Vulnerabilidades pendientes: ${totalVulns - resolvedCount}
— Cobertura de remediación: ${totalVulns > 0 ? Math.round((resolvedCount / totalVulns) * 100) : 0}%`;

  const concLines = doc.splitTextToSize(conclusions, contentW);
  doc.text(concLines, margin, y);
  y += concLines.length * 4 + 20;

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
  doc.text('Equipo de Auditoría de Seguridad', margin, y);

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
  doc.text('DOCUMENTO CONFIDENCIAL — Distribución restringida al equipo de seguridad autorizado', 105, y + 6.5, { align: 'center' });

  
  // ═══════════════════════════════════════
  // ANEXO 12: EVIDENCIAS FOTOGRÁFICAS
  // ═══════════════════════════════════════
  doc.addPage();
  sectionPages['evidencias'] = doc.getNumberOfPages();
  y = 25;

  doc.setTextColor(...COLORS.accent);
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  chapterMap['anexo3'] = String(chapterNum++); doc.text(`${chapterMap['anexo3']}. Anexo: Evidencias Fotográficas`, margin, y);
  y += 15;

  // Evidencia 1
  if (ZAP_EVIDENCE_1) {
    const imgHeight = 60;
    checkPage(imgHeight + 20);
    doc.addImage(ZAP_EVIDENCE_1, 'JPEG', margin, y, contentW, imgHeight);
    y += imgHeight + 5;
    doc.setFont('helvetica', 'italic');
    doc.setFontSize(8);
    doc.text('Figura 1. Vista general del dashboard de OWASP ZAP.', margin + contentW / 2, y, { align: 'center' });
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
    doc.text('Figura 2. Detalle de vulnerabilidades escaneadas por OWASP ZAP.', margin + contentW / 2, y, { align: 'center' });
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
  // ANEXO 10: CRITERIO DE CLASIFICACIÓN
  // ═══════════════════════════════════════
  doc.addPage();
  y = 25;

  doc.setTextColor(...COLORS.accent);
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  chapterMap['anexo2'] = String(chapterNum++); doc.text(`${chapterMap['anexo2']}. Anexo: Criterio de Clasificación de Riesgo`, margin, y);
  y += 10;

  doc.setTextColor(80, 80, 80);
  doc.setFontSize(9);
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
  // RELLENAR ÍNDICE (TOC) EN LA PÁGINA RESERVADA
  // ═══════════════════════════════════════
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

  const tocItems = [
    { num: chapterMap['acuerdo'], title: 'Acuerdo de Confidencialidad', page: String(sectionPages['confidencialidad'] || '') },
    { num: chapterMap['alcance'], title: 'Alcance y Objetivo Técnico', page: String(sectionPages['alcance'] || '') },
    { num: chapterMap['metodologia'], title: 'Metodología y Herramientas', page: String(sectionPages['metodologia'] || '') },
    { num: chapterMap['resumen'], title: 'Resumen de Resultados y Matriz de Riesgo', page: String(sectionPages['matrizRiesgo'] || '') },
    { num: chapterMap['detalle'], title: 'Detalles de Vulnerabilidades y Mitigación Técnica', page: String(sectionPages['detalle'] || '') },
    { num: chapterMap['riesgo'], title: 'Evaluación de Riesgo', page: String(sectionPages['evaluacionRiesgo'] || '') },
    { num: chapterMap['owasp'], title: 'Alineación con OWASP Top 10 (2025)', page: String(sectionPages['owasp'] || '') },
    ...(chapterMap['mozilla'] ? [{ num: chapterMap['mozilla'], title: 'Mozilla Observatory Security Tests', page: String(sectionPages['observatory'] || '') }] : []),
    ...(chapterMap['spider'] ? [{ num: chapterMap['spider'], title: 'Superficie de Ataque (Spider/Crawler)', page: String(sectionPages['spider'] || '') }] : []),
    { num: chapterMap['auditoria'], title: 'Registro de Auditoría (Cadena de Custodia)', page: String(sectionPages['auditoria'] || '') },
    { num: chapterMap['conclusiones'], title: 'Conclusiones y Recomendaciones', page: String(sectionPages['conclusiones'] || '') },
    { num: chapterMap['anexo2'], title: 'Anexo: Criterio de Clasificación de Riesgo', page: String(sectionPages['anexoCriterio'] || '') },
    { num: chapterMap['anexo3'], title: 'Anexo: Evidencias Fotográficas', page: String(sectionPages['evidencias'] || '') },
    { num: chapterMap['anexo4'], title: 'Anexo: Glosario', page: String(sectionPages['glosario'] || '') },
    { num: chapterMap['referencias'], title: 'Referencias Bibliográficas', page: String(sectionPages['referencias'] || '') }
  ].filter(item => item.num !== undefined && item.num !== 'undefined');

  tocItems.forEach(item => {
    doc.setTextColor(...COLORS.gray);
    doc.setFontSize(11);
    doc.setFont('helvetica', 'normal');
    doc.text(item.num + '.', margin, tocY);
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
  for (let i = 2; i <= totalPages; i++) {
    doc.setPage(i);
    addPageHeader();
    addPageFooter(i);
  }

  // ═══ GUARDAR ═══

  const filename = `Playbook_Tecnico_${data.target.replace(/[^a-zA-Z0-9]/g, '_')}_${new Date().toISOString().split('T')[0]}.pdf`;
  doc.save(filename);
}
