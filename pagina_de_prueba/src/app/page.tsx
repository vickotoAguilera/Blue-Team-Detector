import Link from 'next/link';

export default function Home() {
  return (
    <div className="min-h-screen bg-slate-50 font-sans text-slate-800">
      <header className="bg-slate-900 text-white p-6 shadow-md">
        <div className="max-w-5xl mx-auto flex justify-between items-center">
          <h1 className="text-2xl font-bold tracking-tight">TrustAccounting<span className="text-blue-500">.Corp</span></h1>
          <nav className="flex gap-4">
            <Link href="/" className="hover:text-blue-400 transition-colors">Inicio</Link>
            <Link href="/search" className="hover:text-blue-400 transition-colors">Facturación</Link>
            <a href="#login" className="hover:text-blue-400 transition-colors">Portal de Socios</a>
          </nav>
        </div>
      </header>

      <main className="max-w-5xl mx-auto py-12 px-6">
        <section className="text-center py-16 bg-white border border-slate-200 rounded-2xl shadow-sm mb-12">
          <h2 className="text-4xl font-extrabold text-slate-900 mb-4">Gestión Contable sin Fronteras</h2>
          <p className="text-lg text-slate-600 max-w-2xl mx-auto mb-8">Nuestra plataforma "100% segura" procesa nóminas, facturación y activos para cientos de empresas, ofreciendo soluciones de extremo a extremo.</p>
          <Link href="/search" className="bg-blue-600 text-white font-bold py-3 px-8 rounded-full shadow-lg hover:bg-blue-700 transition-all">
            Buscar mis Facturas
          </Link>
        </section>

        <section id="login" className="grid grid-cols-1 md:grid-cols-2 gap-8 items-center">
          <div>
            <h3 className="text-2xl font-bold text-slate-900 mb-4">Portal de Socios Administradores</h3>
            <p className="text-slate-600 mb-6">Inicie sesión en nuestro sistema de bases de datos para gestionar operaciones financieras y balances contables.</p>
          </div>
          
          <div className="bg-white p-8 rounded-xl shadow border border-slate-200">
             <form method="POST" action="/api/login" className="flex flex-col gap-4">
                <div>
                  <label className="block text-sm font-semibold text-slate-700 mb-1">Usuario / Email</label>
                  <input type="text" name="username" className="w-full border border-slate-300 rounded-lg p-2 focus:ring-2 focus:ring-blue-500 focus:outline-none" placeholder="usuario@trustaccounting.corp" />
                </div>
                <div>
                  <label className="block text-sm font-semibold text-slate-700 mb-1">Contraseña segura</label>
                  <input type="password" name="password" className="w-full border border-slate-300 rounded-lg p-2 focus:ring-2 focus:ring-blue-500 focus:outline-none" placeholder="******" />
                </div>
                <button type="submit" className="w-full bg-slate-900 text-white font-bold py-2 rounded-lg hover:bg-slate-800 transition-colors mt-2">
                  Ingresar a Base de Datos
                </button>
             </form>
          </div>
        </section>
      </main>

      <footer className="bg-slate-900 text-slate-400 py-8 text-center mt-12">
        <p>© 2026 TrustAccounting Corp. Todos los derechos reservados.</p>
        <p className="text-sm mt-2 opacity-50">Sistema presuntamente blindado contra vulnerabilidades.</p>
      </footer>
    </div>
  );
}
