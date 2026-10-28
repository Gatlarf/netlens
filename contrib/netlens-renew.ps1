<#
 netlens-renew.ps1 - get a new client certificate from Netlens before the current one ends (Enterprise: Settings -> Host agents). PowerShell 7.4 or newer.

 A certificate that Netlens issued is valid for 30 days and the collector does not renew it by itself. Run this once a day from a scheduled task (as SYSTEM): it does
 nothing until the certificate has fewer than -RenewDays days left, then it makes a NEW key and request, asks Netlens for a certificate by presenting the current
 one, replaces agent.key and agent.crt and restarts the service named by -Service. The old certificate keeps working for up to 7 days, so a failed restart does not
 lose the host. A certificate that has already ended cannot renew: enrol again with a new token (Settings -> Host agents -> Enrol again).

 Example:  pwsh -File C:\ProgramData\netlens-agent\netlens-renew.ps1 -RenewUrl https://netlens.example.com:4318/renew -Service otelcol-contrib
#>
param(
  [Parameter(Mandatory = $true)][string]$RenewUrl,
  [string]$Dir = $PSScriptRoot,
  [string]$Service = "",
  [int]$RenewDays = 20
)
$ErrorActionPreference = "Stop"
$curl = if ($IsWindows) { "curl.exe" } else { "curl" }
$crtPath = Join-Path $Dir "agent.crt"; $keyPath = Join-Path $Dir "agent.key"; $caPath = Join-Path $Dir "ca.pem"

$text = Get-Content -Raw -Path $crtPath
$first = [regex]::Match($text, "-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", "Singleline").Value
$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem($first)
if ($cert.NotAfter.ToUniversalTime() -gt (Get-Date).ToUniversalTime().AddDays($RenewDays)) { return }

$key = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve]::CreateFromFriendlyName("nistP256"))
$name = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [System.Net.Dns]::GetHostName() }
$req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new("CN=$name", $key, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
$tmp = Join-Path $Dir ("renew-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  Set-Content -Path (Join-Path $tmp "agent.csr") -Value $req.CreateSigningRequestPem()
  Set-Content -Path (Join-Path $tmp "agent.key") -Value $key.ExportPkcs8PrivateKeyPem()
  & $curl --silent --show-error --fail --max-time 30 --cacert $caPath --cert $crtPath --key $keyPath --data-binary "@$(Join-Path $tmp 'agent.csr')" $RenewUrl -o (Join-Path $tmp "agent.crt")
  if ($LASTEXITCODE -ne 0) { throw "renewal refused or Netlens not reachable" }
  $new = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem(
    [regex]::Match((Get-Content -Raw -Path (Join-Path $tmp "agent.crt")), "-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", "Singleline").Value)
  if (($new.PublicKey.ExportSubjectPublicKeyInfo() -join ",") -ne ($key.ExportSubjectPublicKeyInfo() -join ",")) { throw "key and certificate do not match" }
  if ($IsWindows) {      # the key stays readable for SYSTEM and the administrators only
    icacls (Join-Path $tmp "agent.key") /inheritance:r /grant:r "SYSTEM:(R)" "BUILTIN\Administrators:(F)" | Out-Null
  }
  Move-Item -Force (Join-Path $tmp "agent.key") $keyPath
  Move-Item -Force (Join-Path $tmp "agent.crt") $crtPath
  Write-Output ("renewed: valid until " + $new.NotAfter.ToUniversalTime().ToString("u"))
  if ($Service) { Restart-Service -Name $Service }
}
finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
