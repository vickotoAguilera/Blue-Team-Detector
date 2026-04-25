import { NextResponse } from 'next/server';

export async function POST(request: Request) {
  const { username, password } = await request.json();

  // VULNERABILIDAD INTENCIONAL (CWE-89 SQL Injection)
  // Simulando una consulta construida mediante concatenación directa de cadenas.
  // Un Red Team podría evadir esto enviando username = "admin' OR '1'='1"
  
  const simulatedSqlQuery = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  
  console.log("Ejecutando SQL en la Agencia:", simulatedSqlQuery);

  // Lógica fraudulenta de bypass
  if (username.includes("' OR '1'='1") || (username === 'admin' && password === 'admin123')) {
    return NextResponse.json({ success: true, token: "VULNERABLE-AUTH-TOKEN-12345" });
  }

  return NextResponse.json({ success: false, error: 'Credenciales inválidas' }, { status: 401 });
}
