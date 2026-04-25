<div align="center">

# 🛡️ Ethical Hacking Verification Portal

### AI-Powered Vulnerability Management & Security Assessment

[![Next.js](https://img.shields.io/badge/Next.js-16-black?logo=next.js)](https://nextjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-blue?logo=typescript)](https://www.typescriptlang.org/)
[![Groq](https://img.shields.io/badge/AI-Groq%20LLaMA%203.3-purple)](https://groq.com/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

*A professional-grade cybersecurity dashboard that combines real-time vulnerability scanning with AI-powered analysis and automated PDF report generation.*

</div>

---

## 🇬🇧 English

### What is this?

The **Ethical Hacking Verification Portal** is a web-based security assessment tool designed for cybersecurity professionals and ethical hackers. It integrates multiple scanning engines and an AI assistant to streamline vulnerability detection, analysis, and remediation.

### ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🧪 **Simulation Mode** | Run simulated scans against a test target to practice and demonstrate capabilities |
| 🌐 **Real Scan Mode** | Perform live HTTP header analysis and Mozilla Observatory checks on real targets |
| 🤖 **AI-Powered Analysis** | Groq LLaMA 3.3 70B provides instant remediation code and risk assessment in Spanish |
| 🕷️ **Spider/Crawler** | Automated endpoint discovery with AI analysis per endpoint |
| 📊 **Visual Analytics** | Real-time charts: severity pie chart, risk bar chart, OWASP radar |
| 📄 **PDF Reports** | Two encrypted PDF outputs: Executive Report (for clients) and Technical Playbook (for engineers) |
| 🔐 **Credential Vault** | Auto-generated secure passwords for each PDF, with copy-to-clipboard |
| 📋 **Audit Log** | Immutable, timestamped log of every action performed during the session |

### 🛠️ Tech Stack

- **Frontend:** Next.js 16 + TypeScript + Tailwind CSS
- **AI Engine:** Groq Cloud API (LLaMA 3.3 70B)
- **PDF Engine:** jsPDF + jsPDF-AutoTable
- **Scanning:** Mozilla Observatory API + Custom HTTP Header Analysis
- **Charts:** Recharts (Pie, Bar, Radar)
- **Icons:** Lucide React

### 🚀 Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/your-username/your-repo.git
cd your-repo

# 2. Install dependencies
cd dashboard
npm install

# 3. Configure environment variables
#    Create a .env.local file in the dashboard/ folder:
echo "GROQ_API_KEY=your_groq_api_key_here" > .env.local

# 4. Run the development server
npm run dev
```

Then open [http://localhost:3000](http://localhost:3000) in your browser.

### ⚙️ Configuration & Customization

#### 🖼️ Logo
Replace the Base64 string in `dashboard/src/lib/logoBase64.ts` with your own logo. Convert your image to Base64:
```bash
node -e "const fs=require('fs'); console.log('data:image/png;base64,'+fs.readFileSync('your-logo.png').toString('base64'))"
```

#### 📸 Scanner Evidence Photos
Edit `dashboard/src/lib/zapEvidence.ts` and paste your Base64-encoded screenshots. Each variable corresponds to a figure in the PDF report:
- `ZAP_EVIDENCE_1` → Figure 1: OWASP ZAP Dashboard
- `ZAP_EVIDENCE_2` → Figure 2: Vulnerability Details
- `ZAP_EVIDENCE_3` → Figure 3: Alert Listing
- `MOZILLA_EVIDENCE_1` → Figure 4: Mozilla Observatory Results

#### 🏢 Organization Name
Search for `"Empresa Default"` in:
- `dashboard/src/lib/generateReport.ts`
- `dashboard/src/lib/generateTechnicalReport.ts`

Replace with your organization's name.

#### 👤 Auditor Names
Search for `"Auditor en Jefe"` and `"Equipo de Seguridad"` in the same files above.

### 📄 PDF Reports

The system generates two password-protected PDF documents:

1. **Executive Report** — Client-facing, APA 7th edition format, includes vulnerability summary, risk matrices, OWASP classification, and photographic evidence.
2. **Technical Playbook** — Engineer-facing, includes AI-generated remediation code per vulnerability, CIA impact analysis, OWASP Risk Rating methodology, and step-by-step patching instructions.

### 🔑 Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GROQ_API_KEY` | ✅ | Your Groq Cloud API key for AI analysis |

---

## 🇪🇸 Español

### ¿Qué es esto?

El **Verificador de Ethical Hacking** es una herramienta de evaluación de seguridad basada en web, diseñada para profesionales de ciberseguridad y hackers éticos. Integra múltiples motores de escaneo y un asistente de IA para agilizar la detección, análisis y remediación de vulnerabilidades.

### ✨ Características Principales

| Característica | Descripción |
|----------------|-------------|
| 🧪 **Modo Simulación** | Ejecuta escaneos simulados contra un objetivo de prueba |
| 🌐 **Escaneo Real** | Análisis en vivo de cabeceras HTTP y verificación con Mozilla Observatory |
| 🤖 **Análisis con IA** | Groq LLaMA 3.3 70B provee código de remediación y evaluación de riesgo en español |
| 🕷️ **Spider/Crawler** | Descubrimiento automático de endpoints con análisis IA por cada uno |
| 📊 **Analítica Visual** | Gráficos en tiempo real: pastel de severidad, barras de riesgo, radar OWASP |
| 📄 **Reportes PDF** | Dos PDFs encriptados: Informe Ejecutivo (para clientes) y Playbook Técnico (para ingenieros) |
| 🔐 **Bóveda de Credenciales** | Contraseñas seguras autogeneradas para cada PDF |
| 📋 **Log de Auditoría** | Registro inmutable y con marca de tiempo de cada acción |

### 🚀 Inicio Rápido

```bash
# 1. Clonar el repositorio
git clone https://github.com/your-username/your-repo.git
cd your-repo

# 2. Instalar dependencias
cd dashboard
npm install

# 3. Configurar variables de entorno
#    Crear un archivo .env.local en la carpeta dashboard/:
echo "GROQ_API_KEY=tu_clave_api_groq_aqui" > .env.local

# 4. Ejecutar el servidor de desarrollo
npm run dev
```

Luego abre [http://localhost:3000](http://localhost:3000) en tu navegador.

### ⚙️ Configuración y Personalización

#### 🖼️ Logo
Reemplaza el string Base64 en `dashboard/src/lib/logoBase64.ts` con tu propio logo.

#### 📸 Fotos de Evidencia del Escáner
Edita `dashboard/src/lib/zapEvidence.ts` y pega tus capturas de pantalla en Base64.

#### 🏢 Nombre de la Organización
Busca `"Empresa Default"` en los archivos de generación de reportes y reemplázalo.

#### 👤 Nombres de Auditores
Busca `"Auditor en Jefe"` y `"Equipo de Seguridad"` en los mismos archivos.

---

## 📁 Project Structure

```
├── dashboard/               # Next.js application
│   ├── src/
│   │   ├── app/
│   │   │   ├── api/
│   │   │   │   ├── scan/        # Simulation scan endpoint
│   │   │   │   ├── real-scan/   # Real HTTP + Observatory scan
│   │   │   │   ├── real-spider/ # Real spider/crawler
│   │   │   │   └── translate/   # Groq AI translation endpoint
│   │   │   ├── page.tsx         # Main dashboard UI
│   │   │   └── layout.tsx       # Root layout
│   │   └── lib/
│   │       ├── generateReport.ts          # Executive PDF generator
│   │       ├── generateTechnicalReport.ts # Technical PDF generator
│   │       ├── logoBase64.ts              # Logo (replace with yours)
│   │       ├── toolLogos.ts               # Tool logos for reports
│   │       └── zapEvidence.ts             # Evidence photos (add yours)
│   ├── .env.local           # Your API keys (not tracked)
│   └── package.json
└── README.md
```

## 📜 License

This project is open source and available under the [MIT License](LICENSE).

---

<div align="center">
  <sub>Built with ❤️ by cybersecurity enthusiasts</sub>
</div>
