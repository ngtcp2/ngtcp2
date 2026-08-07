param(
  [Parameter(Mandatory = $true)]
  [string]$TestExecutable
)

$ErrorActionPreference = "Stop"

$rsa = $null
$generatedCertificate = $null
$certificate = $null
$store = $null
$exitCode = 1

try {
  $rsa = [System.Security.Cryptography.RSA]::Create(2048)
  $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
    "CN=localhost",
    $rsa,
    [System.Security.Cryptography.HashAlgorithmName]::SHA256,
    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

  $san = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
  $san.AddDnsName("localhost")
  $request.CertificateExtensions.Add($san.Build())
  $request.CertificateExtensions.Add(
    [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new(
      $false, $false, 0, $true))
  $request.CertificateExtensions.Add(
    [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
      [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature,
      $true))

  $oids = [System.Security.Cryptography.OidCollection]::new()
  [void]$oids.Add([System.Security.Cryptography.Oid]::new(
    "1.3.6.1.5.5.7.3.1"))
  $request.CertificateExtensions.Add(
    [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new(
      $oids, $true))

  $generatedCertificate = $request.CreateSelfSigned(
    [System.DateTimeOffset]::UtcNow.AddMinutes(-5),
    [System.DateTimeOffset]::UtcNow.AddDays(1))
  $pfx = $generatedCertificate.Export(
    [System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx)
  $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
    $pfx,
    [string]::Empty,
    [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet)

  $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
    [System.Security.Cryptography.X509Certificates.StoreName]::My,
    [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
  $store.Open(
    [System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
  $store.Add($certificate)

  $env:NGTCP2_SCHANNEL_TEST_CERT_HASH = $certificate.Thumbprint
  & $TestExecutable
  $exitCode = $LASTEXITCODE
}
finally {
  Remove-Item Env:\NGTCP2_SCHANNEL_TEST_CERT_HASH -ErrorAction SilentlyContinue
  if ($null -ne $store) {
    if ($null -ne $certificate) {
      $store.Remove($certificate)
    }
    $store.Dispose()
  }
  if ($null -ne $certificate) {
    $certificate.Dispose()
  }
  if ($null -ne $generatedCertificate) {
    $generatedCertificate.Dispose()
  }
  if ($null -ne $rsa) {
    $rsa.Dispose()
  }
}

exit $exitCode
