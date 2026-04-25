'use client';

import { useSearchParams } from 'next/navigation';
import { Suspense } from 'react';
import Link from 'next/link';

function SearchResults() {
  const searchParams = useSearchParams();
  const query = searchParams.get('q');

  if (!query) return (
    <p className="text-slate-500 mt-4">Ingrese un término para buscar clientes o facturas en nuestro sistema.</p>
  );

  return (
    <div className="mt-6 p-4 bg-red-50 border border-red-200 text-red-900 rounded">
      <h3 className="font-semibold">Resultados para:</h3>
      {/* VULNERABILIDAD INTENCIONAL (CWE-79 Cross-Site Scripting) */}
      {/* Imprimiendo variables GET directamente sin validación (Reflected XSS) */}
      <div 
        dangerouslySetInnerHTML={{ __html: query }} 
        className="font-mono text-xl mt-2 overflow-hidden" 
      />
      <p className="mt-4 text-sm text-gray-500">No se encontraron clientes que coincidan con su criterio en nuestra base de datos.</p>
    </div>
  );
}

export default function VulnerableSearch() {
  return (
    <div className="min-h-screen bg-slate-50 font-sans text-slate-800">
      <header className="bg-slate-900 text-white p-6 shadow-md">
        <div className="max-w-5xl mx-auto flex justify-between items-center">
          <h1 className="text-2xl font-bold tracking-tight">TrustAccounting<span className="text-blue-500">.Corp</span></h1>
          <nav className="flex gap-4">
            <Link href="/" className="hover:text-blue-400 transition-colors">Inicio</Link>
            <Link href="/search" className="hover:text-blue-400 transition-colors text-blue-400">Facturación</Link>
            <Link href="/#login" className="hover:text-blue-400 transition-colors">Portal de Socios</Link>
          </nav>
        </div>
      </header>

      <main className="max-w-2xl mx-auto py-12 px-6">
        <div className="bg-white p-8 rounded-xl shadow-lg border border-slate-200">
          <h2 className="text-2xl font-bold text-slate-800 mb-2">Búsqueda Internacional de Facturas</h2>
          <p className="text-slate-600 mb-6">Portal exclusivo para agentes contables de nuestra empresa.</p>
          
          <form className="flex gap-2" method="GET" action="/search">
            <input 
              type="text" 
              name="q" 
              className="flex-1 border border-slate-300 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 text-black"
              placeholder="Buscar por RUT, nombre o número de factura..."
            />
            <button type="submit" className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 font-semibold transition-colors">
              Buscar
            </button>
          </form>

          <Suspense fallback={<p className="mt-4 text-slate-400">Cargando resultados...</p>}>
            <SearchResults />
          </Suspense>
        </div>
      </main>

      <footer className="bg-slate-900 text-slate-400 py-8 text-center mt-auto">
        <p>© 2026 TrustAccounting Corp. Todos los derechos reservados.</p>
      </footer>
    </div>
  );
}
