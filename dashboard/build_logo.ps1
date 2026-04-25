$imgPath = "c:\Users\vicko\Desktop\blue team\docs\informe\logo inacap.jpg"
$outPath = "c:\Users\vicko\Desktop\blue team\dashboard\src\lib\logoBase64.ts"
$bytes = [IO.File]::ReadAllBytes($imgPath)
$b64 = [Convert]::ToBase64String($bytes)
$content = "export const logoBase64 = `"data:image/jpeg;base64,$b64`";"
Set-Content -Path $outPath -Value $content -Encoding UTF8 -NoNewline
Write-Host "Logo INACAP convertido: $($bytes.Length) bytes -> $($b64.Length) chars base64"
