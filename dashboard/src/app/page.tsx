'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import {
  ShieldAlert, ShieldCheck, Activity, Terminal, CheckCircle,
  Search, FileKey, ServerCrash, AlertTriangle, Globe, Zap,
  Lock, Bug, Radar, ArrowRight, ExternalLink, Crosshair, FileDown,
  Copy, RefreshCw, Eye, EyeOff
} from 'lucide-react';
import { generatePDFReport } from '@/lib/generateReport';
import { generateTechnicalReport } from '@/lib/generateTechnicalReport';
import { logoBase64 } from '@/lib/logoBase64';
import ReactMarkdown from 'react-markdown';
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, RadarChart, PolarGrid, PolarAngleAxis,
  PolarRadiusAxis, Radar as RadarShape
} from 'recharts';

interface Alert {
  id: string;
  source: string;
  cweId: string;
  cveId?: string;
  owaspCategory: string;
  name: string;
  severity: string;
  riskScore: number;
  description: string;
  affectedUrl: string;
  evidence: string;
  timestamp: string;
  header?: string;
  recommendation?: string;
  aiRemediation?: string;
  translation?: string;
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

interface SpiderResult {
  url: string;
  method: string;
  status: number;
  type: string;
}

interface ScanSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

interface AuditLog {
  action: string;
  timestamp: string;
  type: 'info' | 'scan' | 'ai' | 'patch' | 'error' | 'spider' | 'real';
}

const SEV_COLORS: Record<string, string> = {
  Critical: '#ef4444', High: '#f97316', Medium: '#eab308', Low: '#3b82f6',
};

export default function Dashboard() {
  const [roeAccepted, setRoeAccepted] = useState(false);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [spiderResults, setSpiderResults] = useState<SpiderResult[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [aiTranslation, setAiTranslation] = useState('');
  const [loadingTranslation, setLoadingTranslation] = useState(false);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [patchedAlerts, setPatchedAlerts] = useState<string[]>([]);
  const [patchInput, setPatchInput] = useState('');
  const [scanTarget, setScanTarget] = useState('');
  const [scanSummary, setScanSummary] = useState<ScanSummary | null>(null);
  const [patchingStatus, setPatchingStatus] = useState('');
  const [scanPhase, setScanPhase] = useState('');
  const [activeTab, setActiveTab] = useState<'intelligence' | 'spider' | 'charts'>('intelligence');
  const [observatoryGrade, setObservatoryGrade] = useState('');
  const [scanMode, setScanMode] = useState<'simulation' | 'real'>('simulation');
  const [realTargetInput, setRealTargetInput] = useState('');
  const [selectedSpider, setSelectedSpider] = useState<SpiderResult | null>(null);
  const [spiderAnalysis, setSpiderAnalysis] = useState('');
  const [loadingSpider, setLoadingSpider] = useState(false);
  const [realHeaders, setRealHeaders] = useState<Record<string, string>>({});
  const [observatoryTests, setObservatoryTests] = useState<Array<{name: string; pass: boolean; result: string; scoreModifier: number; description: string}>>([]);
  const [observatoryScore, setObservatoryScore] = useState(0);
  const [selectedObsTest, setSelectedObsTest] = useState<{name: string; pass: boolean; result: string; scoreModifier: number; description: string} | null>(null);

  const [clientPdfPassword, setClientPdfPassword] = useState('');
  const [techPdfPassword, setTechPdfPassword] = useState('');
  const [showPasswords, setShowPasswords] = useState(false);


  const mounted = useRef(false);

  const generateSecureKey = () => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$*()_+-=';
    let key = 'BT-';
    for (let i = 0; i < 8; i++) {
        key += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return key;
  };

  const regenerateKeys = () => {
    setClientPdfPassword(generateSecureKey());
    setTechPdfPassword(generateSecureKey());
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const addLog = useCallback((action: string, type: AuditLog['type'] = 'info') => {
    setAuditLogs(prev => [{ action, timestamp: new Date().toISOString(), type }, ...prev]);
  }, []);

  useEffect(() => {
    if (!mounted.current) {
      mounted.current = true;
      setClientPdfPassword(generateSecureKey());
      setTechPdfPassword(generateSecureKey());
      addLog('Sistema de Ciberseguridad Ethical Hacking Verifier inicializado.', 'info');
      addLog('Esperando aceptación de RoE...', 'info');
    }
  }, [addLog]);

  // ── Simulated Scan ──
  const handleSimulatedScan = async () => {
    setIsScanning(true);
    setSelectedAlert(null);
    setAiTranslation('');
    setActiveTab('intelligence');

    setScanPhase('spider');
    addLog('🕷️ Fase 1: Spider/Crawler sobre objetivo simulado...', 'spider');
    await new Promise(r => setTimeout(r, 1500));
    setScanPhase('observatory');
    addLog('🔍 Fase 2: Mozilla Observatory (headers)...', 'scan');
    await new Promise(r => setTimeout(r, 1200));
    setScanPhase('zap');
    addLog('⚡ Fase 3: OWASP ZAP Active Scan...', 'scan');
    await new Promise(r => setTimeout(r, 1500));

    try {
      const res = await fetch('/api/scan');
      const data = await res.json();
      setAlerts(data.alerts.map((a: Alert) => ({ ...a, affectedUrl: a.affectedUrl || data.target, evidence: a.evidence || '' })));
      setSpiderResults(data.spiderResults);
      setScanTarget(data.target);
      setScanSummary(data.summary);
      setObservatoryGrade(data.observatoryGrade);
      addLog(`Objetivo: ${data.target} — ${data.totalAlerts} vulnerabilidades [C:${data.summary.critical} H:${data.summary.high} M:${data.summary.medium} L:${data.summary.low}]`, 'scan');
    } catch {
      addLog('ERROR: Fallo de conexión.', 'error');
    } finally {
      setIsScanning(false);
      setScanPhase('');
    }
  };

  // ── Real Scan ──
  const handleRealScan = async () => {
    if (!realTargetInput.trim()) return;
    let targetUrl = realTargetInput.trim();
    if (!targetUrl.startsWith('http')) targetUrl = 'https://' + targetUrl;

    setIsScanning(true);
    setSelectedAlert(null);
    setAiTranslation('');
    setActiveTab('intelligence');
    setSpiderResults([]);
    setRealHeaders({});

    // Fase 1: Spider Real
    setScanPhase('spider');
    addLog(`🕷️ [REAL] Ejecutando Spider sobre ${targetUrl}...`, 'spider');
    try {
      const spiderRes = await fetch(`/api/real-spider?target=${encodeURIComponent(targetUrl)}`);
      const spiderData = await spiderRes.json();
      if (spiderData.endpoints) {
        const mapped = spiderData.endpoints.map((ep: { url: string; method: string; type: string; context?: string }) => ({
          url: ep.url, method: ep.method, status: 200, type: ep.type, context: ep.context || '',
        }));
        setSpiderResults(mapped);
        addLog(`🕷️ [REAL] Spider descubrió ${mapped.length} endpoints.`, 'spider');
      }
    } catch {
      addLog('⚠️ Spider: no se pudo rastrear el objetivo.', 'error');
    }

    // Fase 2: Headers + Observatory
    setScanPhase('headers');
    addLog(`🌐 [REAL] Analizando cabeceras HTTP...`, 'real');
    await new Promise(r => setTimeout(r, 800));
    setScanPhase('observatory');
    addLog('🔍 [REAL] Consultando Mozilla Observatory API...', 'real');

    try {
      const res = await fetch(`/api/real-scan?target=${encodeURIComponent(targetUrl)}`);
      const data = await res.json();

      if (data.error) {
        addLog(`ERROR: ${data.error}`, 'error');
        setIsScanning(false);
        setScanPhase('');
        return;
      }

      setScanTarget(targetUrl);
      setRealHeaders(data.headers || {});
      setObservatoryGrade(data.observatoryGrade || 'N/A');

      const realAlerts: Alert[] = (data.missingHeaders || []).map((h: { id: string; header: string; cweId: string; owaspCategory: string; severity: string; riskScore: number; description: string; recommendation: string }) => ({
        id: h.id,
        source: h.header === 'connection-error' ? 'Conexión Directa' : 'Análisis HTTP Headers + Mozilla Observatory',
        cweId: h.cweId,
        owaspCategory: h.owaspCategory,
        name: `${h.header.toUpperCase()} — Cabecera faltante`,
        severity: h.severity,
        riskScore: h.riskScore,
        description: h.description,
        affectedUrl: targetUrl,
        evidence: `Header "${h.header}" no encontrado en la respuesta HTTP del servidor.`,
        timestamp: data.scanDate,
        header: h.header,
        recommendation: h.recommendation,
      }));

      setAlerts(realAlerts);
      setScanSummary(data.summary);
      setObservatoryTests(data.observatoryTests || []);
      setObservatoryScore(data.observatoryScore || 0);
      addLog(`✅ [REAL] Escaneo completado: ${data.totalAlerts} cabeceras faltantes.`, 'real');
      addLog(`[REAL] Observatory Grade: ${data.observatoryGrade} (${data.observatoryScore}/100)`, 'real');
    } catch {
      addLog('ERROR: No se pudo conectar al objetivo.', 'error');
    } finally {
      setIsScanning(false);
      setScanPhase('');
    }
  };

  // ── Generate PDF Report ──
  const handleGenerateReport = () => {
    addLog('Generando Informe PDF de Evaluación de Vulnerabilidades...', 'info');
    generatePDFReport({
      target: scanTarget,
      alerts,
      patchedAlerts,
      auditLogs,
      spiderResults,
      scanSummary,
      observatoryGrade,
      observatoryScore,
      observatoryTests,
      scanMode,
    }, clientPdfPassword);
    addLog('[OK] Informe Ejecutivo generado y descargado.', 'info');
  };

  // ── Generate Technical Playbook (Batch AI) ──
  const [isGeneratingTech, setIsGeneratingTech] = useState(false);

  const handleGenerateTechnicalReport = async () => {
    if (alerts.length === 0) return;
    setIsGeneratingTech(true);
    addLog('Generando Playbook Técnico... Iniciando análisis AI en Batch.', 'ai');
    
    // Create a copy of alerts to enrich with AI remediation
    const enrichedAlerts = [...alerts];

    // Fetch AI Remediation for each alert sequentially to not overload GROQ limit
    for (let i = 0; i < enrichedAlerts.length; i++) {
        if (patchedAlerts.includes(enrichedAlerts[i].id)) continue;
        
        try {
            const res = await fetch('/api/translate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    cweId: enrichedAlerts[i].cweId, 
                    name: enrichedAlerts[i].name,
                    description: enrichedAlerts[i].description, 
                    owaspCategory: enrichedAlerts[i].owaspCategory,
                    affectedUrl: enrichedAlerts[i].affectedUrl,
                    nvdData: enrichedAlerts[i].nvdData,
                })
            });
            const data = await res.json();
            enrichedAlerts[i].aiRemediation = data.translation;
            addLog(`Analizado [${i+1}/${alerts.length}]: ${enrichedAlerts[i].cweId}`, 'ai');
        } catch {
            enrichedAlerts[i].aiRemediation = "Error al obtener la remediación de la IA.";
        }
    }

    generateTechnicalReport({
      target: scanTarget,
      alerts: enrichedAlerts,
      patchedAlerts,
      auditLogs,
      spiderResults,
      scanSummary,
      observatoryGrade,
      observatoryScore,
      observatoryTests,
      scanMode,
    }, techPdfPassword);
    
    addLog('[OK] Technical Playbook descargado.', 'info');
    setIsGeneratingTech(false);
  };

  // ── Select Alert ──
  const handleSelectAlert = async (alert: Alert) => {
    if (patchedAlerts.includes(alert.id)) return;
    setSelectedAlert(alert);
    setAiTranslation('');
    setPatchInput('');
    setLoadingTranslation(true);
    setActiveTab('intelligence');
    addLog(`Solicitando análisis IA para ${alert.cweId}`, 'ai');

    try {
      const res = await fetch('/api/translate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          cweId: alert.cweId, name: alert.name,
          description: alert.description, owaspCategory: alert.owaspCategory,
          affectedUrl: alert.affectedUrl,
          nvdData: alert.nvdData,
        })
      });
      const data = await res.json();
      setAiTranslation(data.translation);
      addLog(`Traducción IA recibida para ${alert.cweId}.`, 'ai');
    } catch {
      setAiTranslation('Error al obtener traducción.');
      addLog(`ERROR: Fallo motor IA para ${alert.cweId}`, 'error');
    } finally {
      setLoadingTranslation(false);
    }
  };

  // ── Spider AI Analysis ──
  const handleSpiderClick = async (sr: SpiderResult) => {
    setSelectedSpider(sr);
    setSpiderAnalysis('');
    setLoadingSpider(true);
    addLog(`🕷️ Analizando endpoint con IA: ${sr.url}`, 'spider');

    try {
      const res = await fetch('/api/translate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          cweId: 'SPIDER-ANALYSIS',
          name: `Análisis de Endpoint: ${sr.method} ${sr.url}`,
          description: `El spider descubrió este endpoint durante la fase de reconocimiento preventivo. Método HTTP: ${sr.method}. Código de respuesta: ${sr.status}. Tipo de recurso: ${sr.type}. URL completa: ${sr.url}. Analiza qué tipo de recurso es, qué riesgos de seguridad podría tener según su tipo y método, y qué debería verificar el equipo de ciberseguridad para protegerlo.`,
          owaspCategory: 'Reconocimiento de Superficie de Ataque',
          affectedUrl: sr.url,
        })
      });
      const data = await res.json();
      setSpiderAnalysis(data.translation);
      addLog(`Análisis de spider recibido para ${sr.url}`, 'spider');
    } catch {
      setSpiderAnalysis('Error al analizar endpoint.');
    } finally {
      setLoadingSpider(false);
    }
  };

  // ── Apply Patch ──
  const handleApplyPatch = async () => {
    if (!selectedAlert || !patchInput.trim()) return;
    setPatchingStatus('connecting');
    addLog(`[SSH] Conectando al servidor...`, 'patch');
    await new Promise(r => setTimeout(r, 1200));
    setPatchingStatus('applying');
    addLog(`[WAF] Inyectando regla para ${selectedAlert.cweId}...`, 'patch');
    await new Promise(r => setTimeout(r, 1500));
    setPatchingStatus('verifying');
    addLog(`[WAF] Verificando parche...`, 'patch');
    await new Promise(r => setTimeout(r, 800));
    setPatchedAlerts(prev => [...prev, selectedAlert.id]);
    addLog(`✅ PARCHE: ${selectedAlert.cweId} mitigada. Amenaza bloqueada.`, 'patch');
    setPatchingStatus('');
    setPatchInput('');
    setSelectedAlert(null);
    setAiTranslation('');
  };

  const sevColor = (s: string) => {
    const m: Record<string, string> = {
      Critical: 'bg-red-500/20 text-red-400 border-red-500/30',
      High: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
      Medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
      Low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    };
    return m[s] || '';
  };

  const logColor = (t: AuditLog['type']) => {
    const m: Record<string, string> = { scan: 'text-cyan-400', ai: 'text-purple-400', patch: 'text-green-400', error: 'text-red-400', spider: 'text-amber-400', info: 'text-slate-400', real: 'text-emerald-400' };
    return m[t] || 'text-slate-400';
  };

  const pieData = scanSummary ? [
    { name: 'Críticas', value: scanSummary.critical, color: SEV_COLORS.Critical },
    { name: 'Altas', value: scanSummary.high, color: SEV_COLORS.High },
    { name: 'Medias', value: scanSummary.medium, color: SEV_COLORS.Medium },
    { name: 'Bajas', value: scanSummary.low, color: SEV_COLORS.Low },
  ] : [];

  const barData = alerts.map(a => ({ name: a.cweId, riesgo: a.riskScore, fill: SEV_COLORS[a.severity] }));

  const radarData = [
    { subject: 'Injection', A: alerts.filter(a => a.owaspCategory.includes('Injection')).length * 40, fullMark: 100 },
    { subject: 'Crypto', A: alerts.filter(a => a.owaspCategory.includes('Cryptographic')).length * 40, fullMark: 100 },
    { subject: 'Misconfig', A: alerts.filter(a => a.owaspCategory.includes('Misconfiguration')).length * 20, fullMark: 100 },
    { subject: 'Access', A: alerts.filter(a => a.owaspCategory.includes('Access')).length * 40, fullMark: 100 },
    { subject: 'XSS', A: alerts.filter(a => a.cweId === 'CWE-79').length * 50, fullMark: 100 },
  ];

  const resolvedCount = patchedAlerts.length;

  // ── RoE Gate ──
  if (!roeAccepted) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4">
        <div className="max-w-lg bg-slate-900/80 backdrop-blur border border-slate-800 rounded-2xl p-10 shadow-2xl shadow-slate-900/20 text-slate-200">
          <div className="flex justify-center mb-6">
            <ShieldCheck className="w-20 h-20 text-red-600 animate-pulse" />
          </div>
          <h1 className="text-2xl font-bold text-center mb-2 text-white">Declaración de Reglas de Enfrentamiento (RoE)</h1>
          <p className="text-xs text-center text-slate-500 uppercase tracking-widest mb-6">Acceso Restringido — Equipo de Seguridad</p>
          <div className="bg-slate-950 border border-slate-800 rounded-lg p-4 mb-6 text-sm text-slate-400 space-y-2">
            <p>• Entorno restringido a personal de ciberseguridad autorizado.</p>
            <p>• Certificas poseer autorización para auditar la infraestructura objetivo.</p>
            <p>• Todas las acciones quedan en un log de auditoría inmutable.</p>
            <p>• La información no será compartida fuera del perímetro autorizado.</p>
          </div>
          <button onClick={() => { setRoeAccepted(true); addLog('RoE aceptadas. Módulos habilitados.', 'info'); }}
            className="w-full bg-red-600 hover:bg-red-500 text-white font-bold py-3 px-4 rounded-lg transition-all flex items-center justify-center gap-2 shadow-lg shadow-red-900/30">
            <CheckCircle className="w-5 h-5" /> Acepto — Ingresar al Portal de Seguridad
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 font-sans">
      {/* Header */}
      <header className="border-b border-slate-800 bg-slate-900/50 backdrop-blur sticky top-0 z-50">
        <div className="max-w-[1600px] mx-auto flex items-center justify-between px-6 py-3">
          {/* Left Title Area */}
          <div className="flex flex-col md:flex-row md:items-center gap-4 relative">
            <div className="absolute left-0 top-0 w-32 h-32 bg-red-500/5 blur-[80px] rounded-full pointer-events-none"></div>
            <div className="flex items-center gap-3">
              <img src={logoBase64} alt="Ethical Hacking Verifier Logo" className="w-10 h-10 object-contain drop-shadow-[0_0_8px_rgba(227,6,19,0.3)]" />
              <div>
                <h1 className="text-xl font-bold text-white tracking-tight">Verificador de Ethical Hacking</h1>
                <p className="text-[10px] uppercase tracking-[0.2em] text-slate-500 mb-1">Vulnerability Management & Security Assessment</p>
                <p className="text-[10px] text-slate-400 font-mono flex items-center gap-1.5 flex-wrap">
                  Core: 
                  <a href="https://owasp.org/www-project-top-ten/" target="_blank" rel="noopener noreferrer" className="text-red-400 hover:text-red-300 underline decoration-red-500/30 underline-offset-2 transition-colors flex items-center gap-1">
                    OWASP Top 10 (2025) <ExternalLink className="w-2.5 h-2.5" />
                  </a> 
                  | Scan: 
                  <a href="https://observatory.mozilla.org/" target="_blank" rel="noopener noreferrer" className="text-red-400 hover:text-red-300 underline decoration-red-500/30 underline-offset-2 transition-colors flex items-center gap-1">
                    Mozilla Observatory <ExternalLink className="w-2.5 h-2.5" />
                  </a> 
                  & 
                  <a href="https://www.zaproxy.org/" target="_blank" rel="noopener noreferrer" className="text-red-400 hover:text-red-300 underline decoration-red-500/30 underline-offset-2 transition-colors flex items-center gap-1">
                    ZAP Spider <ExternalLink className="w-2.5 h-2.5" />
                  </a>
                </p>
              </div>
            </div>
          </div>
          
          {/* Right Action Area */}
          <div className="flex items-center gap-2 flex-wrap">
            {scanTarget && (
              <div className="flex items-center gap-1.5 text-xs text-slate-400 bg-slate-800 px-3 py-1.5 rounded-full border border-slate-700">
                <Globe className="w-3 h-3" /> <span className="font-mono text-white truncate max-w-[150px]">{scanTarget}</span>
              </div>
            )}
            {observatoryGrade && (
              <div className={`flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-full border ${observatoryGrade === 'F' || observatoryGrade === 'D' ? 'bg-red-500/10 text-red-400 border-red-500/20' : observatoryGrade.startsWith('A') || observatoryGrade.startsWith('B') ? 'bg-green-500/10 text-green-400 border-green-500/20' : 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20'}`}>
                Obs: <span className="font-bold">{observatoryGrade}</span>
              </div>
            )}
            

            
            {alerts.length > 0 && (
              <div className="flex items-center gap-2 bg-slate-950 border border-slate-700/50 p-1.5 rounded-full shadow-inner">
                {/* Credentials Vault Widget */}
                <div className="flex items-center gap-2 px-2 border-r border-slate-800">
                  <div className="flex flex-col justify-center">
                    <span className="text-[8px] text-slate-500 uppercase font-bold tracking-wider mb-0.5">Bóveda C.</span>
                    <div className="flex items-center gap-1">
                      <button onClick={() => setShowPasswords(!showPasswords)} className="text-slate-400 hover:text-slate-200" title="Mostrar/Ocultar">
                        {showPasswords ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                      </button>
                      <button onClick={regenerateKeys} className="text-blue-400 hover:text-blue-300" title="Regenerar Claves">
                        <RefreshCw className="w-3 h-3" />
                      </button>
                    </div>
                  </div>
                  
                  <div className="flex flex-col gap-1">
                    <div className="flex items-center gap-1.5 bg-slate-900 border border-slate-800 rounded px-1.5 py-0.5">
                      <span className="text-[9px] text-blue-400 font-mono w-[60px] truncate">{showPasswords ? clientPdfPassword : '••••••••'}</span>
                      <button onClick={() => { copyToClipboard(clientPdfPassword); addLog('Clave de Informe Cliente copiada al portapapeles.', 'info'); }} className="text-slate-500 hover:text-white" title="Copiar Clave Cliente"><Copy className="w-2.5 h-2.5" /></button>
                    </div>
                    <div className="flex items-center gap-1.5 bg-slate-900 border border-slate-800 rounded px-1.5 py-0.5">
                      <span className="text-[9px] text-purple-400 font-mono w-[60px] truncate">{showPasswords ? techPdfPassword : '••••••••'}</span>
                      <button onClick={() => { copyToClipboard(techPdfPassword); addLog('Clave de Playbook copiada al portapapeles.', 'info'); }} className="text-slate-500 hover:text-white" title="Copiar Clave Playbook"><Copy className="w-2.5 h-2.5" /></button>
                    </div>
                  </div>
                </div>

                {/* Download Actions */}
                <button onClick={handleGenerateReport}
                  className="flex items-center gap-1.5 text-xs text-slate-900 bg-blue-400 hover:bg-blue-300 font-bold px-3 py-1.5 rounded-full border border-blue-400/50 transition-all shadow-lg shadow-blue-500/20">
                  <FileDown className="w-3 h-3" /> Info Cliente
                </button>
                <button onClick={handleGenerateTechnicalReport} disabled={isGeneratingTech}
                  className="flex items-center gap-1.5 text-xs text-white bg-purple-600 hover:bg-purple-500 disabled:opacity-50 px-3 py-1.5 rounded-full border border-purple-500/30 transition-all shadow-lg shadow-purple-900/20">
                  {isGeneratingTech ? <Activity className="w-3 h-3 animate-spin" /> : <Terminal className="w-3 h-3" />} 
                  {isGeneratingTech ? 'Analizando...' : 'Playbook T.'}
                </button>
              </div>
            )}
            <div className="flex items-center gap-1.5 text-[10px] font-bold tracking-wider text-green-400 bg-green-400/10 px-3 py-1.5 rounded-full border border-green-400/20">
              <Activity className="w-3 h-3 animate-pulse" /> OPERATIVO
            </div>
          </div>
        </div>
      </header>

      <div className="max-w-[1600px] mx-auto p-6">
        {/* Summary Cards */}
        {scanSummary && (
          <div className="grid grid-cols-2 md:grid-cols-6 gap-3 mb-6">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4"><p className="text-[10px] text-slate-500 uppercase">Total</p><p className="text-3xl font-bold text-white">{alerts.length}</p></div>
            <div className="bg-red-950/30 border border-red-900/30 rounded-xl p-4"><p className="text-[10px] text-red-400 uppercase">Críticas</p><p className="text-3xl font-bold text-red-400">{scanSummary.critical}</p></div>
            <div className="bg-orange-950/30 border border-orange-900/30 rounded-xl p-4"><p className="text-[10px] text-orange-400 uppercase">Altas</p><p className="text-3xl font-bold text-orange-400">{scanSummary.high}</p></div>
            <div className="bg-yellow-950/30 border border-yellow-900/30 rounded-xl p-4"><p className="text-[10px] text-yellow-400 uppercase">Medias</p><p className="text-3xl font-bold text-yellow-400">{scanSummary.medium}</p></div>
            <div className="bg-blue-950/30 border border-blue-900/30 rounded-xl p-4"><p className="text-[10px] text-blue-400 uppercase">Bajas</p><p className="text-3xl font-bold text-blue-400">{scanSummary.low}</p></div>
            <div className="bg-green-950/30 border border-green-900/30 rounded-xl p-4"><p className="text-[10px] text-green-400 uppercase">Resueltas</p><p className="text-3xl font-bold text-green-400">{resolvedCount}<span className="text-lg text-slate-500">/{alerts.length}</span></p></div>
          </div>
        )}

        <main className="grid grid-cols-12 gap-6">
          {/* ── Left Column ── */}
          <div className="col-span-12 lg:col-span-4 flex flex-col gap-4">
            {/* Scan Mode Toggle + Scanner */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
              {/* Mode Selector */}
              <div className="flex gap-1 mb-4">
                <button onClick={() => setScanMode('simulation')}
                  className={`flex-1 text-[10px] font-bold py-1.5 rounded transition-all ${scanMode === 'simulation' ? 'bg-blue-600 text-white' : 'bg-slate-800 text-slate-500 hover:text-slate-300'}`}>
                  🧪 SIMULACIÓN
                </button>
                <button onClick={() => setScanMode('real')}
                  className={`flex-1 text-[10px] font-bold py-1.5 rounded transition-all ${scanMode === 'real' ? 'bg-emerald-600 text-white' : 'bg-slate-800 text-slate-500 hover:text-slate-300'}`}>
                  🌐 ESCANEO REAL
                </button>
              </div>

              {scanMode === 'simulation' ? (
                <div className="flex justify-between items-center mb-4">
                  <h2 className="text-sm font-semibold flex items-center gap-2 text-white"><Zap className="w-4 h-4 text-cyan-400" /> Simulación</h2>
                  <button onClick={handleSimulatedScan} disabled={isScanning}
                    className="bg-blue-600 hover:bg-blue-500 disabled:bg-blue-600/50 text-white text-xs font-bold py-2 px-4 rounded-lg flex items-center gap-1.5 transition-all">
                    {isScanning ? <><div className="w-3 h-3 border-2 border-white border-t-transparent rounded-full animate-spin"></div> Escaneando...</> : <><Search className="w-3 h-3" /> Auditar Objetivo</>}
                  </button>
                </div>
              ) : (
                <div className="mb-4">
                  <h2 className="text-sm font-semibold flex items-center gap-2 text-white mb-2"><Crosshair className="w-4 h-4 text-emerald-400" /> Escaneo Real</h2>
                  <div className="bg-amber-950/30 border border-amber-500/20 rounded-lg p-2.5 mb-3">
                    <p className="text-[10px] text-amber-400 leading-relaxed flex gap-1.5">
                      <AlertTriangle className="w-3 h-3 shrink-0 mt-0.5" />
                      <span><strong>⚖️ AVISO LEGAL:</strong> Solo escanee infraestructura de <strong>su propiedad</strong> o con <strong>autorización escrita</strong> del dueño (RoE firmadas). Escanear sistemas de terceros sin permiso es ilegal (Convenio de Budapest, CFAA).</span>
                    </p>
                  </div>
                  <div className="flex gap-2">
                    <input type="text" value={realTargetInput} onChange={e => setRealTargetInput(e.target.value)}
                      className="flex-1 bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-emerald-400 focus:outline-none focus:border-emerald-500/50 placeholder:text-slate-600"
                      placeholder="https://mi-pagina.com (solo sitios propios)" />
                    <button onClick={handleRealScan} disabled={isScanning || !realTargetInput.trim()}
                      className="bg-emerald-600 hover:bg-emerald-500 disabled:bg-emerald-600/30 text-white text-xs font-bold py-2 px-3 rounded-lg flex items-center gap-1 transition-all">
                      {isScanning ? <div className="w-3 h-3 border-2 border-white border-t-transparent rounded-full animate-spin"></div> : <Crosshair className="w-3 h-3" />}
                    </button>
                  </div>
                  <p className="text-[10px] text-slate-600 mt-1.5">Spider + HTTP Headers + Mozilla Observatory API</p>
                </div>
              )}

              {/* Scan Phase */}
              {isScanning && scanPhase && (
                <div className="mb-4 bg-slate-950 border border-cyan-900/30 rounded-lg p-2.5">
                  <div className="flex items-center gap-2 text-xs">
                    <div className="w-2 h-2 bg-cyan-400 rounded-full animate-pulse"></div>
                    <span className="text-cyan-400">
                      {scanPhase === 'spider' && 'Ejecutando Spider/Crawler...'}
                      {scanPhase === 'observatory' && 'Consultando Mozilla Observatory...'}
                      {scanPhase === 'zap' && 'OWASP ZAP Active Scan...'}
                      {scanPhase === 'headers' && 'Analizando cabeceras HTTP...'}
                    </span>
                  </div>
                </div>
              )}

              {/* Alert List */}
              <div className="flex flex-col gap-2 max-h-[340px] overflow-y-auto pr-1">
                {alerts.length === 0 && !isScanning ? (
                  <div className="flex flex-col items-center justify-center text-slate-500 border border-dashed border-slate-800 rounded-lg p-6">
                    <ServerCrash className="w-8 h-8 mb-2 opacity-40" />
                    <p className="text-xs text-center">Sin datos. Inicia un escaneo.</p>
                  </div>
                ) : (
                  alerts.map(alert => {
                    const patched = patchedAlerts.includes(alert.id);
                    const selected = selectedAlert?.id === alert.id;
                    return (
                      <div key={alert.id} onClick={() => handleSelectAlert(alert)}
                        className={`p-3 rounded-lg border transition-all ${patched ? 'border-green-500/30 bg-green-950/20 opacity-60 cursor-default' : selected ? 'border-blue-500 bg-slate-800 cursor-pointer' : 'border-slate-800 bg-slate-950/50 cursor-pointer hover:bg-slate-800'}`}>
                        <div className="flex justify-between items-start mb-1">
                          <span className="text-[10px] font-mono text-slate-400 bg-slate-800 px-1.5 py-0.5 rounded border border-slate-700">{alert.cweId}</span>
                          {patched ? (
                            <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-green-500/20 text-green-400 border border-green-500/30 flex items-center gap-1"><Lock className="w-2.5 h-2.5" /> Resuelta</span>
                          ) : (
                            <span className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded border ${sevColor(alert.severity)}`}>{alert.severity}</span>
                          )}
                        </div>
                        <p className="font-semibold text-xs text-slate-200 line-clamp-1 mt-1">{alert.name}</p>
                        <p className="text-[10px] text-slate-600 mt-1">{alert.source}</p>
                      </div>
                    );
                  })
                )}
              </div>
            </div>

            {/* Audit Log */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex-1">
              <h2 className="text-sm font-semibold flex items-center gap-2 mb-3 text-white"><Terminal className="w-4 h-4 text-slate-400" /> Registro de Auditoría</h2>
              <div className="bg-slate-950 rounded-lg border border-slate-800 p-2.5 h-44 overflow-y-auto space-y-1 font-mono text-[10px]">
                {auditLogs.map((log, i) => (
                  <div key={i} className="flex gap-1.5 leading-relaxed">
                    <span className="text-slate-600 shrink-0">[{new Date(log.timestamp).toLocaleTimeString()}]</span>
                    <span className={`${logColor(log.type)} break-all`}>{log.action}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* ── Right Column ── */}
          <div className="col-span-12 lg:col-span-8">
            <div className="flex gap-1 mb-4">
              {[
                { key: 'intelligence' as const, label: 'Inteligencia IA', icon: <FileKey className="w-3.5 h-3.5" /> },
                { key: 'spider' as const, label: 'Spider/Crawler', icon: <Bug className="w-3.5 h-3.5" /> },
                { key: 'charts' as const, label: 'Analítica Visual', icon: <Radar className="w-3.5 h-3.5" /> },
              ].map(tab => (
                <button key={tab.key} onClick={() => setActiveTab(tab.key)}
                  className={`flex items-center gap-2 px-4 py-2 rounded-t-lg text-xs font-semibold transition-all ${activeTab === tab.key ? 'bg-slate-900 text-white border border-b-0 border-slate-800' : 'bg-slate-950 text-slate-500 hover:text-slate-300'}`}>
                  {tab.icon} {tab.label}
                </button>
              ))}
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl rounded-tl-none p-6 shadow-lg min-h-[600px]">

              {/* ─── TAB: Intelligence ─── */}
              {activeTab === 'intelligence' && (
                <>
                  {!selectedAlert ? (
                    <div className="flex flex-col items-center justify-center h-[500px] text-slate-500 p-6">
                      <AlertTriangle className="w-12 h-12 mb-4 opacity-30" />
                      <p className="italic text-center">Seleccione una vulnerabilidad para solicitar el análisis IA.</p>
                      <p className="text-xs text-slate-600 mt-2 mb-6">Motor: Groq LLaMA 3.3 70B</p>
                      <div className="max-w-md bg-amber-950/20 border border-amber-900/40 rounded-lg p-4 text-center">
                        <p className="text-[10px] text-amber-500/80 leading-relaxed">
                          <strong>⚠️ AVISO DE SUPERVISIÓN:</strong> La Inteligencia Artificial es un Asistente diseñado para mitigar el <em>burnout</em> y estrés del Blue Team mediante sugerencias en tiempo récord. Sus códigos de remediación <strong>siempre deben ser supervisados y validados por un ingeniero humano</strong> antes de ejecutar el parcheo en producción.
                        </p>
                      </div>
                    </div>
                  ) : (
                    <div>
                      <div className="mb-6">
                        <div className="flex items-start justify-between gap-4 mb-3">
                          <h3 className="text-lg font-bold text-white">{selectedAlert.cweId} — {selectedAlert.name}</h3>
                          <span className={`text-xs uppercase font-bold px-3 py-1 rounded border shrink-0 ${sevColor(selectedAlert.severity)}`}>{selectedAlert.severity}</span>
                        </div>
                        <div className="bg-red-950/40 border border-red-900/40 p-3 rounded-lg space-y-1 text-xs">
                          <p className="text-red-400"><strong>OWASP:</strong> {selectedAlert.owaspCategory}</p>
                          <p className="text-red-400/80"><strong>URL:</strong> <code className="bg-red-950 px-1 py-0.5 rounded">{selectedAlert.affectedUrl}</code></p>
                          <p className="text-red-400/60"><strong>Evidencia:</strong> {selectedAlert.evidence}</p>
                        </div>
                        {selectedAlert.nvdData && (
                          <div className="mt-4 bg-blue-950/30 border border-blue-500/30 rounded-lg p-4">
                            <h4 className="text-xs font-bold text-blue-400 mb-2 flex items-center gap-2">
                              <ShieldCheck className="w-4 h-4" /> INFORMACIÓN OFICIAL NVD ({selectedAlert.nvdData.cveId})
                            </h4>
                            <div className="grid grid-cols-2 gap-4 mb-3">
                              <div className="bg-slate-900/50 p-2 rounded border border-slate-800">
                                <p className="text-[10px] text-slate-500 uppercase font-bold">Severidad</p>
                                <p className="text-sm font-bold text-white">{selectedAlert.nvdData.severity}</p>
                              </div>
                              <div className="bg-slate-900/50 p-2 rounded border border-slate-800">
                                <p className="text-[10px] text-slate-500 uppercase font-bold">CVSS Score</p>
                                <p className="text-sm font-bold text-white">{selectedAlert.nvdData.baseScore}/10</p>
                              </div>
                            </div>
                            <div className="space-y-2">
                              <div>
                                <p className="text-[10px] text-slate-500 uppercase font-bold mb-1">Descripción NVD</p>
                                <p className="text-xs text-slate-300 leading-relaxed italic">"{selectedAlert.nvdData.description}"</p>
                              </div>
                              {selectedAlert.nvdData.references && selectedAlert.nvdData.references.length > 0 && (
                                <div>
                                  <p className="text-[10px] text-slate-500 uppercase font-bold mb-1">Referencias</p>
                                  <div className="flex flex-wrap gap-2">
                                    {selectedAlert.nvdData.references.slice(0, 3).map((ref: string, i: number) => (
                                      <a key={i} href={ref} target="_blank" rel="noopener noreferrer" className="text-[10px] text-blue-400 hover:underline flex items-center gap-1">
                                        Ref {i+1} <ExternalLink className="w-2.5 h-2.5" />
                                      </a>
                                    ))}
                                  </div>
                                </div>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                      {loadingTranslation ? (
                        <div className="flex flex-col items-center justify-center p-16 space-y-4">
                          <div className="w-12 h-12 border-4 border-purple-500 border-t-transparent rounded-full animate-spin"></div>
                          <p className="text-purple-400 text-sm animate-pulse">Groq LLaMA 3.3 analizando...</p>
                        </div>
                      ) : aiTranslation && (
                        <>
                          <div className="prose prose-invert prose-sm prose-purple max-w-none text-slate-300 mb-6">
                            <ReactMarkdown>{aiTranslation}</ReactMarkdown>
                          </div>
                          <div className="border-t border-slate-800 pt-6">
                            <h4 className="text-base font-bold text-white mb-1 flex items-center gap-2">
                              <Terminal className="w-4 h-4 text-green-400" /> Consola de Remediación
                            </h4>
                            <textarea className="w-full bg-slate-950 border border-slate-700 rounded-lg p-4 text-sm font-mono text-green-400 focus:outline-none focus:border-green-500/50 resize-none placeholder:text-slate-600"
                              rows={6} placeholder="// Pega aquí el código de remediación..." value={patchInput} onChange={e => setPatchInput(e.target.value)} />
                            {patchingStatus && (
                              <div className="mt-2 bg-slate-950 border border-green-900/30 rounded-lg p-2.5 font-mono text-[11px] text-green-400">
                                <div className="flex items-center gap-2"><div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
                                  {patchingStatus === 'connecting' && 'Conectando vía SSH...'}
                                  {patchingStatus === 'applying' && `Inyectando regla para ${selectedAlert.cweId}...`}
                                  {patchingStatus === 'verifying' && 'Verificando parche...'}
                                </div>
                              </div>
                            )}
                            <div className="mt-3 flex justify-end">
                              <button onClick={handleApplyPatch} disabled={!!patchingStatus || !patchInput.trim()}
                                className="bg-green-600 hover:bg-green-500 disabled:bg-green-600/30 disabled:cursor-not-allowed text-white font-bold py-2.5 px-6 rounded-lg transition-all flex items-center gap-2 shadow-lg shadow-green-900/20">
                                <ShieldCheck className="w-5 h-5" /> {patchingStatus ? 'Aplicando...' : 'Aplicar Parche'}
                              </button>
                            </div>
                          </div>
                        </>
                      )}
                    </div>
                  )}
                </>
              )}

              {/* ─── TAB: Spider ─── */}
              {activeTab === 'spider' && (
                <div>
                  <h3 className="text-lg font-bold text-white mb-1 flex items-center gap-2">
                    <Bug className="w-5 h-5 text-amber-400" /> Spider / Crawler — Mapa de Superficie de Ataque
                  </h3>
                  <p className="text-xs text-slate-400 mb-4">Haz clic en cualquier endpoint para solicitar un análisis de IA detallado.</p>

                  {spiderResults.length === 0 ? (
                    <div className="flex flex-col items-center justify-center h-[400px] text-slate-500 relative overflow-hidden select-none">
                      {/* Telaraña SVG de fondo */}
                      <svg className="absolute inset-0 w-full h-full opacity-[0.06]" viewBox="0 0 400 400">
                        <line x1="200" y1="0" x2="200" y2="400" stroke="#94a3b8" strokeWidth="1"/>
                        <line x1="0" y1="200" x2="400" y2="200" stroke="#94a3b8" strokeWidth="1"/>
                        <line x1="0" y1="0" x2="400" y2="400" stroke="#94a3b8" strokeWidth="1"/>
                        <line x1="400" y1="0" x2="0" y2="400" stroke="#94a3b8" strokeWidth="1"/>
                        <circle cx="200" cy="200" r="40" fill="none" stroke="#94a3b8" strokeWidth="0.5"/>
                        <circle cx="200" cy="200" r="80" fill="none" stroke="#94a3b8" strokeWidth="0.5"/>
                        <circle cx="200" cy="200" r="120" fill="none" stroke="#94a3b8" strokeWidth="0.5"/>
                        <circle cx="200" cy="200" r="160" fill="none" stroke="#94a3b8" strokeWidth="0.5"/>
                        <circle cx="200" cy="200" r="200" fill="none" stroke="#94a3b8" strokeWidth="0.5"/>
                      </svg>

                      {/* Arañas 8-bit animadas */}
                      <style>{`
                        @keyframes spiderCrawl1 {
                          0% { transform: translate(-120px, -80px) scaleX(1); }
                          25% { transform: translate(-30px, -40px) scaleX(1); }
                          50% { transform: translate(40px, 0px) scaleX(-1); }
                          75% { transform: translate(-10px, 30px) scaleX(-1); }
                          100% { transform: translate(-120px, -80px) scaleX(1); }
                        }
                        @keyframes spiderCrawl2 {
                          0% { transform: translate(130px, -70px) scaleX(-1); }
                          30% { transform: translate(50px, -20px) scaleX(-1); }
                          60% { transform: translate(-20px, 10px) scaleX(1); }
                          100% { transform: translate(130px, -70px) scaleX(-1); }
                        }
                        @keyframes spiderCrawl3 {
                          0% { transform: translate(0px, 100px); }
                          40% { transform: translate(-60px, 30px); }
                          70% { transform: translate(30px, -10px) scaleX(-1); }
                          100% { transform: translate(0px, 100px); }
                        }
                        @keyframes spiderLegs {
                          0%, 100% { transform: scaleY(1); }
                          50% { transform: scaleY(0.85); }
                        }
                        @keyframes webPulse {
                          0%, 100% { opacity: 0.06; }
                          50% { opacity: 0.12; }
                        }
                        @keyframes threadDrop {
                          0% { height: 0px; opacity: 0; }
                          30% { opacity: 0.4; }
                          100% { height: 60px; opacity: 0.15; }
                        }
                        .spider-pixel {
                          image-rendering: pixelated;
                          font-size: 28px;
                          filter: drop-shadow(0 0 6px rgba(245,158,11,0.4));
                        }
                        .spider-1 { animation: spiderCrawl1 8s ease-in-out infinite, spiderLegs 0.3s ease-in-out infinite; }
                        .spider-2 { animation: spiderCrawl2 10s ease-in-out infinite 1s, spiderLegs 0.25s ease-in-out infinite; }
                        .spider-3 { animation: spiderCrawl3 12s ease-in-out infinite 2s, spiderLegs 0.35s ease-in-out infinite; }
                        .web-bg { animation: webPulse 4s ease-in-out infinite; }
                        .thread { animation: threadDrop 3s ease-out infinite; }
                      `}</style>

                      {/* Representación de página web objetivo (8-bit frame) */}
                      <div className="relative z-10 border-2 border-dashed border-amber-500/30 rounded-lg p-6 bg-slate-950/60 backdrop-blur w-[280px]">
                        {/* Barra de título del navegador retro */}
                        <div className="flex items-center gap-1.5 mb-3 pb-2 border-b border-amber-500/20">
                          <div className="w-2 h-2 rounded-full bg-red-500/60"></div>
                          <div className="w-2 h-2 rounded-full bg-yellow-500/60"></div>
                          <div className="w-2 h-2 rounded-full bg-green-500/60"></div>
                          <div className="flex-1 bg-slate-800 rounded h-3 ml-2 flex items-center px-2">
                            <span className="text-[7px] text-amber-500/50 font-mono">https://target.site/</span>
                          </div>
                        </div>
                        {/* Líneas de "contenido" simulado */}
                        <div className="space-y-1.5">
                          <div className="h-1.5 bg-slate-700/40 rounded w-3/4"></div>
                          <div className="h-1.5 bg-slate-700/30 rounded w-full"></div>
                          <div className="h-1.5 bg-slate-700/20 rounded w-5/6"></div>
                          <div className="h-1.5 bg-amber-500/10 rounded w-2/3 mt-2"></div>
                          <div className="h-1.5 bg-slate-700/15 rounded w-4/5"></div>
                        </div>
                        {/* Texto central */}
                        <p className="text-center text-[10px] text-amber-500/60 mt-4 font-mono tracking-wider">ESPERANDO OBJETIVO...</p>
                      </div>

                      {/* Las 3 arañas pixel caminando hacia el sitio */}
                      <div className="spider-pixel spider-1 absolute z-20">🕷️</div>
                      <div className="spider-pixel spider-2 absolute z-20">🕷️</div>
                      <div className="spider-pixel spider-3 absolute z-20" style={{fontSize: '20px'}}>🕷️</div>

                      {/* Hilos de araña cayendo */}
                      <div className="thread absolute top-0 left-[30%] w-[1px] bg-gradient-to-b from-amber-500/30 to-transparent"></div>
                      <div className="thread absolute top-0 left-[70%] w-[1px] bg-gradient-to-b from-amber-500/20 to-transparent" style={{animationDelay: '1.5s'}}></div>

                      {/* Texto inferior */}
                      <p className="relative z-10 italic text-xs mt-4">{scanMode === 'real' ? 'El modo Real no incluye Spider (solo disponible en Simulacion).' : 'Ejecute un escaneo simulado para activar el Spider.'}</p>
                      <p className="relative z-10 text-[9px] text-amber-500/40 mt-1 font-mono">{'>'} CRAWLERS EN ESPERA {'<'}</p>
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 gap-4">
                      <div className="bg-slate-950 border border-slate-800 rounded-lg overflow-hidden">
                        <table className="w-full text-xs">
                          <thead>
                            <tr className="border-b border-slate-800 text-slate-500 uppercase text-[10px]">
                              <th className="text-left p-3">URL</th>
                              <th className="text-center p-3">Método</th>
                              <th className="text-center p-3">Status</th>
                              <th className="text-center p-3">Tipo</th>
                              <th className="text-center p-3">Acción</th>
                            </tr>
                          </thead>
                          <tbody>
                            {spiderResults.map((sr, i) => (
                              <tr key={i} onClick={() => handleSpiderClick(sr)}
                                className={`border-b border-slate-800/50 cursor-pointer transition-colors ${selectedSpider?.url === sr.url ? 'bg-amber-500/10' : 'hover:bg-slate-800/30'}`}>
                                <td className="p-3 font-mono text-cyan-400">{sr.url}</td>
                                <td className="p-3 text-center"><span className={`px-2 py-0.5 rounded text-[10px] font-bold ${sr.method === 'POST' ? 'bg-orange-500/20 text-orange-400' : 'bg-blue-500/20 text-blue-400'}`}>{sr.method}</span></td>
                                <td className="p-3 text-center"><span className={`font-mono ${sr.status === 200 ? 'text-green-400' : 'text-red-400'}`}>{sr.status}</span></td>
                                <td className="p-3 text-center text-slate-500">{sr.type}</td>
                                <td className="p-3 text-center"><ExternalLink className="w-3 h-3 text-amber-400 mx-auto" /></td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>

                      {/* Spider AI Analysis */}
                      {selectedSpider && (
                        <div className="bg-slate-950 border border-amber-900/30 rounded-xl p-5">
                          <h4 className="text-sm font-bold text-amber-400 mb-1 flex items-center gap-2">
                            <Bug className="w-4 h-4" /> Análisis IA: {selectedSpider.method} {selectedSpider.url}
                          </h4>
                          {loadingSpider ? (
                            <div className="flex items-center gap-3 p-6">
                              <div className="w-6 h-6 border-3 border-amber-500 border-t-transparent rounded-full animate-spin"></div>
                              <p className="text-amber-400 text-xs animate-pulse">Analizando endpoint...</p>
                            </div>
                          ) : spiderAnalysis && (
                            <div className="prose prose-invert prose-sm prose-amber max-w-none text-slate-300 mt-3">
                              <ReactMarkdown>{spiderAnalysis}</ReactMarkdown>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  )}

                  {/* Real Headers Display */}
                  {scanMode === 'real' && Object.keys(realHeaders).length > 0 && (
                    <div className="mt-6">
                      <h4 className="text-sm font-bold text-emerald-400 mb-3">Cabeceras HTTP recibidas del servidor</h4>
                      <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 max-h-[250px] overflow-y-auto font-mono text-[11px]">
                        {Object.entries(realHeaders).map(([key, value]) => (
                          <div key={key} className="flex gap-2 py-0.5">
                            <span className="text-emerald-400 shrink-0">{key}:</span>
                            <span className="text-slate-400 break-all">{value}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* ─── TAB: Charts ─── */}
              {activeTab === 'charts' && (
                <div>
                  <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                    <Radar className="w-5 h-5 text-purple-400" /> Analítica Visual de Postura de Seguridad
                  </h3>

                  {/* Observatory Score + Tests Panel */}
                  {observatoryTests.length > 0 && (
                    <div className="bg-slate-950 border border-slate-800 rounded-xl p-5 mb-6">
                      <div className="flex items-center justify-between mb-4">
                        <h4 className="text-sm font-bold text-white flex items-center gap-2">
                          <Globe className="w-4 h-4 text-blue-400" /> Mozilla Observatory — Tests Detallados
                        </h4>
                        <div className="flex items-center gap-3">
                          <div className="text-center">
                            <div className={`text-3xl font-black ${observatoryScore >= 80 ? 'text-green-400' : observatoryScore >= 50 ? 'text-yellow-400' : 'text-red-400'}`}>
                              {observatoryScore}<span className="text-sm text-slate-500">/100</span>
                            </div>
                            <p className="text-[9px] text-slate-500 uppercase">Puntuación</p>
                          </div>
                          <div className={`w-14 h-14 rounded-full flex items-center justify-center text-2xl font-black border-4 ${observatoryGrade === 'A+' || observatoryGrade === 'A' ? 'border-green-500 text-green-400 bg-green-500/10' : observatoryGrade === 'B+' || observatoryGrade === 'B' ? 'border-blue-500 text-blue-400 bg-blue-500/10' : observatoryGrade === 'C+' || observatoryGrade === 'C' ? 'border-yellow-500 text-yellow-400 bg-yellow-500/10' : 'border-red-500 text-red-400 bg-red-500/10'}`}>
                            {observatoryGrade}
                          </div>
                        </div>
                      </div>
                      <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
                        {observatoryTests.map((test, i) => (
                          <div key={i} onClick={() => setSelectedObsTest(selectedObsTest?.name === test.name ? null : test)}
                            className={`rounded-lg p-3 border transition-all cursor-pointer hover:scale-[1.03] ${test.pass ? 'bg-green-950/20 border-green-900/30 hover:border-green-500/50' : 'bg-red-950/30 border-red-900/40 hover:border-red-500/50'} ${selectedObsTest?.name === test.name ? 'ring-2 ring-blue-500 scale-[1.03]' : ''}`}>
                            <div className="flex items-center gap-1.5 mb-1">
                              {test.pass ? (
                                <CheckCircle className="w-3.5 h-3.5 text-green-400 shrink-0" />
                              ) : (
                                <ShieldAlert className="w-3.5 h-3.5 text-red-400 shrink-0" />
                              )}
                              <span className={`text-[10px] font-bold ${test.pass ? 'text-green-400' : 'text-red-400'}`}>{test.pass ? 'PASS' : 'FAIL'}</span>
                              {test.scoreModifier !== 0 && (
                                <span className={`text-[9px] ml-auto ${test.scoreModifier > 0 ? 'text-green-500' : 'text-red-500'}`}>
                                  {test.scoreModifier > 0 ? '+' : ''}{test.scoreModifier}
                                </span>
                              )}
                            </div>
                            <p className="text-[10px] font-semibold text-white leading-tight">{test.name}</p>
                            <p className="text-[9px] text-slate-500 mt-0.5 leading-tight line-clamp-2">{test.description}</p>
                          </div>
                        ))}
                      </div>

                      {/* Detail Panel for selected test */}
                      {selectedObsTest && (
                        <div className={`mt-4 rounded-xl p-4 border ${selectedObsTest.pass ? 'bg-green-950/10 border-green-900/30' : 'bg-red-950/20 border-red-900/40'}`}>
                          <div className="flex items-start justify-between mb-3">
                            <div className="flex items-center gap-2">
                              {selectedObsTest.pass ? (
                                <CheckCircle className="w-5 h-5 text-green-400" />
                              ) : (
                                <ShieldAlert className="w-5 h-5 text-red-400" />
                              )}
                              <div>
                                <h5 className="text-sm font-bold text-white">{selectedObsTest.name}</h5>
                                <p className={`text-xs font-bold ${selectedObsTest.pass ? 'text-green-400' : 'text-red-400'}`}>
                                  {selectedObsTest.pass ? '✅ TEST APROBADO' : '❌ TEST REPROBADO'}
                                </p>
                              </div>
                            </div>
                            <div className="flex gap-2">
                              {selectedObsTest.scoreModifier !== 0 && (
                                <span className={`text-xs font-bold px-2 py-1 rounded-lg ${selectedObsTest.scoreModifier > 0 ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>
                                  {selectedObsTest.scoreModifier > 0 ? '+' : ''}{selectedObsTest.scoreModifier} pts
                                </span>
                              )}
                              <button onClick={() => setSelectedObsTest(null)} className="text-slate-500 hover:text-white text-xs">✕</button>
                            </div>
                          </div>

                          <div className="space-y-3 text-xs text-slate-300">
                            <div>
                              <p className="text-[10px] text-slate-500 uppercase font-bold mb-1">descripción completa</p>
                              <p>{selectedObsTest.description}</p>
                            </div>
                            <div>
                              <p className="text-[10px] text-slate-500 uppercase font-bold mb-1">estado del test</p>
                              <p>{selectedObsTest.result}</p>
                            </div>
                            <div>
                              <p className="text-[10px] text-slate-500 uppercase font-bold mb-1">impacto en la puntuación</p>
                              <p>{selectedObsTest.scoreModifier === 0
                                ? 'Este test no modifica la puntuación base (peso neutro).'
                                : selectedObsTest.scoreModifier > 0
                                  ? `Este test suma ${selectedObsTest.scoreModifier} puntos a la puntuación total como bonificación por buenas prácticas de seguridad.`
                                  : `Este test resta ${Math.abs(selectedObsTest.scoreModifier)} puntos de la puntuación total. Esta es una de las principales razones de la nota actual.`
                              }</p>
                            </div>
                            <div>
                              <p className="text-[10px] text-slate-500 uppercase font-bold mb-1">recomendación</p>
                              <p>{selectedObsTest.pass
                                ? `✅ ${selectedObsTest.name} está correctamente configurado. No se requiere acción.`
                                : `⚠️ Implementar ${selectedObsTest.name} en la configuración del servidor web (Nginx, Apache, Cloudflare). Esto es crítico para mejorar la nota de Observatory.`
                              }</p>
                            </div>
                          </div>
                        </div>
                      )}

                      {/* Progress bar */}
                      <div className="mt-4">
                        <div className="flex justify-between text-[10px] text-slate-500 mb-1">
                          <span>Tests: {observatoryTests.filter(t => t.pass).length}/{observatoryTests.length} pasados</span>
                          <span>{observatoryScore} pts</span>
                        </div>
                        <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                          <div className={`h-full rounded-full transition-all duration-1000 ${observatoryScore >= 80 ? 'bg-green-500' : observatoryScore >= 50 ? 'bg-yellow-500' : 'bg-red-500'}`}
                            style={{ width: `${observatoryScore}%` }}></div>
                        </div>
                      </div>
                    </div>
                  )}

                  {alerts.length === 0 && observatoryTests.length === 0 ? (
                    <div className="flex flex-col items-center justify-center h-[500px] text-slate-500 relative overflow-hidden select-none">
                      <style>{`
                        @keyframes radarSweep {
                          0% { transform: rotate(0deg); }
                          100% { transform: rotate(360deg); }
                        }
                        @keyframes blipAppear1 {
                          0%, 60% { opacity: 0; transform: scale(0); }
                          65% { opacity: 1; transform: scale(1.5); }
                          70% { opacity: 0.8; transform: scale(1); }
                          100% { opacity: 0; transform: scale(0.5); }
                        }
                        @keyframes blipAppear2 {
                          0%, 30% { opacity: 0; transform: scale(0); }
                          35% { opacity: 1; transform: scale(1.5); }
                          40% { opacity: 0.8; transform: scale(1); }
                          100% { opacity: 0; transform: scale(0.5); }
                        }
                        @keyframes blipAppear3 {
                          0%, 75% { opacity: 0; transform: scale(0); }
                          80% { opacity: 1; transform: scale(1.8); }
                          85% { opacity: 0.6; transform: scale(1); }
                          100% { opacity: 0; transform: scale(0.5); }
                        }
                        @keyframes blipAppear4 {
                          0%, 10% { opacity: 0; transform: scale(0); }
                          15% { opacity: 1; transform: scale(1.3); }
                          25% { opacity: 0.7; transform: scale(1); }
                          100% { opacity: 0; transform: scale(0.3); }
                        }
                        @keyframes blipAppear5 {
                          0%, 50% { opacity: 0; transform: scale(0); }
                          55% { opacity: 0.9; transform: scale(1.6); }
                          65% { opacity: 0.5; transform: scale(1); }
                          100% { opacity: 0; transform: scale(0.4); }
                        }
                        @keyframes radarPulse {
                          0%, 100% { opacity: 0.15; }
                          50% { opacity: 0.25; }
                        }
                        @keyframes scanlineMove {
                          0% { top: 0%; }
                          100% { top: 100%; }
                        }
                        .radar-sweep {
                          animation: radarSweep 4s linear infinite;
                        }
                        .radar-blip-1 { animation: blipAppear1 4s ease-out infinite; }
                        .radar-blip-2 { animation: blipAppear2 4s ease-out infinite; }
                        .radar-blip-3 { animation: blipAppear3 4s ease-out infinite; }
                        .radar-blip-4 { animation: blipAppear4 4s ease-out infinite; }
                        .radar-blip-5 { animation: blipAppear5 4s ease-out infinite; }
                      `}</style>

                      {/* Radar Container */}
                      <div className="relative w-[300px] h-[300px]">
                        {/* Círculos concéntricos del radar */}
                        <svg className="absolute inset-0 w-full h-full" viewBox="0 0 300 300">
                          {/* Retícula / Grid */}
                          <circle cx="150" cy="150" r="140" fill="none" stroke="#22c55e" strokeWidth="0.8" opacity="0.15"/>
                          <circle cx="150" cy="150" r="105" fill="none" stroke="#22c55e" strokeWidth="0.5" opacity="0.12"/>
                          <circle cx="150" cy="150" r="70" fill="none" stroke="#22c55e" strokeWidth="0.5" opacity="0.1"/>
                          <circle cx="150" cy="150" r="35" fill="none" stroke="#22c55e" strokeWidth="0.5" opacity="0.08"/>
                          {/* Cruz central */}
                          <line x1="150" y1="10" x2="150" y2="290" stroke="#22c55e" strokeWidth="0.3" opacity="0.1"/>
                          <line x1="10" y1="150" x2="290" y2="150" stroke="#22c55e" strokeWidth="0.3" opacity="0.1"/>
                          <line x1="50" y1="50" x2="250" y2="250" stroke="#22c55e" strokeWidth="0.2" opacity="0.06"/>
                          <line x1="250" y1="50" x2="50" y2="250" stroke="#22c55e" strokeWidth="0.2" opacity="0.06"/>
                          {/* Punto central */}
                          <circle cx="150" cy="150" r="3" fill="#22c55e" opacity="0.6"/>
                        </svg>

                        {/* Barrido del radar (cono verde que gira) */}
                        <div className="radar-sweep absolute inset-0" style={{transformOrigin: '150px 150px'}}>
                          <svg className="w-full h-full" viewBox="0 0 300 300">
                            <defs>
                              <linearGradient id="sweepGrad" gradientTransform="rotate(0, 0.5, 0.5)">
                                <stop offset="0%" stopColor="#22c55e" stopOpacity="0"/>
                                <stop offset="100%" stopColor="#22c55e" stopOpacity="0.35"/>
                              </linearGradient>
                            </defs>
                            <path d="M150,150 L150,10 A140,140 0 0,1 248,52 Z" fill="url(#sweepGrad)"/>
                            {/* Línea del barrido */}
                            <line x1="150" y1="150" x2="150" y2="10" stroke="#22c55e" strokeWidth="1.5" opacity="0.7">
                            </line>
                          </svg>
                        </div>

                        {/* Blips / Puntos que aparecen y desaparecen */}
                        <div className="radar-blip-1 absolute w-2.5 h-2.5 bg-green-400 rounded-full shadow-[0_0_8px_#22c55e]" style={{top: '25%', left: '60%'}}></div>
                        <div className="radar-blip-2 absolute w-2 h-2 bg-green-400 rounded-full shadow-[0_0_6px_#22c55e]" style={{top: '55%', left: '30%'}}></div>
                        <div className="radar-blip-3 absolute w-3 h-3 bg-red-400 rounded-full shadow-[0_0_10px_#ef4444]" style={{top: '40%', left: '70%'}}></div>
                        <div className="radar-blip-4 absolute w-2 h-2 bg-green-400 rounded-full shadow-[0_0_6px_#22c55e]" style={{top: '70%', left: '55%'}}></div>
                        <div className="radar-blip-5 absolute w-1.5 h-1.5 bg-yellow-400 rounded-full shadow-[0_0_6px_#eab308]" style={{top: '35%', left: '40%'}}></div>

                        {/* Borde exterior brillante */}
                        <div className="absolute inset-0 rounded-full border border-green-500/20 shadow-[inset_0_0_30px_rgba(34,197,94,0.05)]"></div>
                      </div>

                      {/* Texto inferior */}
                      <div className="mt-6 text-center relative z-10">
                        <p className="text-green-500/70 font-mono text-sm tracking-widest mb-1">RADAR INACTIVO</p>
                        <p className="text-slate-600 italic text-xs">Ejecute un escaneo para activar el analisis de postura.</p>
                        <p className="text-green-500/30 font-mono text-[9px] mt-2 tracking-[0.3em]">AWAITING TELEMETRY...</p>
                      </div>
                    </div>
                  ) : alerts.length > 0 && (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <div className="bg-slate-950 border border-slate-800 rounded-xl p-4">
                        <h4 className="text-sm font-semibold text-white mb-3">Distribución por Severidad</h4>
                        <ResponsiveContainer width="100%" height={220}>
                          <PieChart>
                            <Pie data={pieData} cx="50%" cy="50%" innerRadius={50} outerRadius={80} dataKey="value" animationBegin={0} animationDuration={1200}>
                              {pieData.map((entry, i) => (<Cell key={i} fill={entry.color} />))}
                            </Pie>
                            <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px', fontSize: '12px' }} />
                          </PieChart>
                        </ResponsiveContainer>
                        <div className="flex justify-center gap-4 mt-2">
                          {pieData.map((d, i) => (
                            <div key={i} className="flex items-center gap-1.5 text-[10px] text-slate-400">
                              <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: d.color }}></div>{d.name}: {d.value}
                            </div>
                          ))}
                        </div>
                      </div>
                      <div className="bg-slate-950 border border-slate-800 rounded-xl p-4">
                        <h4 className="text-sm font-semibold text-white mb-3">Riesgo por CWE</h4>
                        <ResponsiveContainer width="100%" height={250}>
                          <BarChart data={barData}>
                            <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 10 }} />
                            <YAxis tick={{ fill: '#94a3b8', fontSize: 10 }} domain={[0, 10]} />
                            <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px', fontSize: '12px' }} />
                            <Bar dataKey="riesgo" animationDuration={1500} radius={[4, 4, 0, 0]}>
                              {barData.map((entry, i) => (<Cell key={i} fill={entry.fill} />))}
                            </Bar>
                          </BarChart>
                        </ResponsiveContainer>
                      </div>
                      <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 md:col-span-2">
                        <h4 className="text-sm font-semibold text-white mb-3">Cobertura OWASP Top 10</h4>
                        <ResponsiveContainer width="100%" height={280}>
                          <RadarChart cx="50%" cy="50%" outerRadius="70%" data={radarData}>
                            <PolarGrid stroke="#1e293b" />
                            <PolarAngleAxis dataKey="subject" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                            <PolarRadiusAxis tick={{ fill: '#475569', fontSize: 9 }} />
                            <RadarShape name="Exposición" dataKey="A" stroke="#a855f7" fill="#a855f7" fillOpacity={0.3} animationDuration={1500} />
                          </RadarChart>
                        </ResponsiveContainer>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}
