using System.Security.Cryptography;
using System.Text;
using System.Security.Cryptography.Pkcs;
using microauthd.Config;
using Serilog;

namespace microauthd.Common;

public static class TokenCertManager
{
    /// <summary>
    /// Ensures that a valid authentication keypair exists for token signing.
    /// </summary>
    /// <remarks>This method verifies the presence of a keypair based on the provided configuration  and
    /// creates one if it does not exist. The keypair is used for signing authentication tokens.</remarks>
    /// <param name="config">The application configuration containing the settings for the token signing keypair,  including the file path,
    /// passphrase, and preferred key type.</param>
    public static string EnsureAuthKeypair(AppConfig config)
    {
        return EnsureKeypair(
            config.TokenSigningKeyFile,
            config.TokenSigningKeyPassphrase,
            config.PreferECDSASigningKey,
            config.TokenSigningKeyLengthRSA
        );
    }

    /// <summary>
    /// Ensures that the administrative keypair required for token signing is available.
    /// </summary>
    /// <remarks>This method verifies the existence of the administrative keypair and creates it if necessary,
    /// using the settings provided in the <paramref name="config"/> object. The keypair is used for  signing
    /// administrative tokens, and its configuration may include preferences for specific  cryptographic algorithms,
    /// such as ECDSA.</remarks>
    /// <param name="config">The application configuration containing the settings for the administrative keypair, including file paths,
    /// passphrase, and key preferences.</param>
    public static string EnsureAdminKeypair(AppConfig config)
    {
        return EnsureKeypair(
            config.AdminTokenSigningKeyFile,
            config.AdminTokenSigningKeyPassphrase,
            config.PreferECDSAAdminSigningKey,
            config.AdminTokenSigningKeyLengthRSA
        );
    }

    /// <summary>
    /// Ensures that a cryptographic key pair exists at the specified path. If no key pair is found, a new one is
    /// generated using either ECDSA or RSA, based on the specified preference.
    /// </summary>
    /// <remarks>If a key pair already exists at the specified path, no action is taken. If a new key pair is
    /// generated, the method logs the type of key created (ECDSA or RSA) and its location.</remarks>
    /// <param name="path">The file path where the key pair is stored or will be generated. Cannot be null or empty.</param>
    /// <param name="passphrase">An optional passphrase used to encrypt the key pair. If null, the key pair will not be encrypted.</param>
    /// <param name="preferECDsa">A value indicating whether to prefer generating an ECDSA key pair.  If <see langword="true"/>, an ECDSA key pair
    /// is generated; otherwise, an RSA key pair is generated.</param>
    private static string EnsureKeypair(string keyPath, string? passphrase, bool preferECDsa, int rsaKeyBits)
    {
        string pubKeyPath = GetPublicKeyPath(keyPath);
        return EnsurePrivateKeyAndExportPublic(keyPath, passphrase, preferECDsa, pubKeyPath, rsaKeyBits);
    }

    /// <summary>
    /// Ensures that a private key exists at the specified path and exports the corresponding public key. If a private
    /// key is found at the specified path, the public key is exported. If no private key is found, a new private key is
    /// generated, saved to the specified path, and the public key is exported.
    /// </summary>
    /// <remarks>This method handles both the creation and retrieval of private keys. If a private key already
    /// exists at the specified path,  it is loaded and used to export the public key. If no private key exists, a new
    /// key is generated based on the specified  <paramref name="preferECDsa"/> value, saved to the specified path, and
    /// the public key is exported.</remarks>
    /// <param name="keyPath">The file path where the private key is stored or will be generated.</param>
    /// <param name="passphrase">The passphrase used to encrypt the private key. If <see langword="null"/> or empty, the private key will be
    /// saved unencrypted.</param>
    /// <param name="preferECDsa">A value indicating whether to prefer generating an ECDSA key. If <see langword="true"/>, an ECDSA key is
    /// generated;  otherwise, an RSA key is generated.</param>
    /// <param name="publicKeyOutPath">The file path where the public key will be exported.</param>
    public static string EnsurePrivateKeyAndExportPublic(
    string keyPath,
    string? passphrase,
    bool preferECDsa,
    string publicKeyOutPath,
    int rsaKeyBits)
    {
        try
        {
            AsymmetricAlgorithm key;

            if (File.Exists(keyPath))
            {
                Log.Information("Found existing private key at {Path}", keyPath);
                key = LoadPrivateKey(keyPath, passphrase);

                bool isEc = key is ECDsa;
                bool isRsa = key is RSA;

                if (preferECDsa && isRsa)
                {
                    Log.Warning("PreferECDSA was true, but existing key at {Path} is RSA. No new key will be generated.", keyPath);
                    Console.WriteLine($"Warning: You requested an EC key, but the existing key at '{keyPath}' is RSA. Keeping existing RSA key.");
                }
                else if (!preferECDsa && isEc)
                {
                    Log.Warning("PreferECDSA was false, but existing key at {Path} is ECDSA. No new key will be generated.", keyPath);
                    Console.WriteLine($"Warning: You requested an RSA key, but the existing key at '{keyPath}' is EC. Keeping existing EC key.");
                }

                ExportPublicKey(key, publicKeyOutPath);
            }
            else
            {
                Log.Information("No private key found at {Path}, generating new key...", keyPath);

                key = preferECDsa
                    ? ECDsa.Create(ECCurve.NamedCurves.nistP256)
                    : RSA.Create(rsaKeyBits);

                string pem = string.IsNullOrWhiteSpace(passphrase)
                    ? ExportPrivateKeyUnencrypted(key)
                    : ExportPrivateKeyEncrypted(key, passphrase!);

                File.WriteAllText(keyPath, pem);
                ExportPublicKey(key, publicKeyOutPath);

                Log.Information("Generated new {Type} private key at {Path}", preferECDsa ? "ECDSA" : "RSA", keyPath);
            }

            string keyId = GenerateKeyIdFromPublicKey(key);
            Log.Information("KeyId for {Path} is: {KeyId}", keyPath, keyId);
            return keyId;
        }
        catch (Exception ex)
        {
            Log.Fatal(ex, "Failed to load or create signing key {Path}: {msg}", keyPath, ex.Message);
            Console.WriteLine($"Error handling signing key at {keyPath}: {ex.Message}");
            Environment.Exit(1);
            return string.Empty; // unreachable, but compiler-safe
        }
    }


    /// <summary>
    /// Exports the private key of the specified asymmetric algorithm in unencrypted PKCS#8 format.
    /// </summary>
    /// <remarks>This method exports the private key in an unencrypted format, which may pose security risks
    /// if the key is exposed. Ensure that the exported key is handled securely and stored in a safe location.</remarks>
    /// <param name="key">The asymmetric algorithm instance containing the private key to export. Must be an instance of <see cref="RSA"/>
    /// or <see cref="ECDsa"/>.</param>
    /// <returns>A PEM-encoded string representing the unencrypted PKCS#8 private key.</returns>
    /// <exception cref="NotSupportedException">Thrown if the <paramref name="key"/> is not an instance of <see cref="RSA"/> or <see cref="ECDsa"/>.</exception>
    private static string ExportPrivateKeyUnencrypted(AsymmetricAlgorithm key)
    {
        byte[] pkcs8 = key switch
        {
            RSA rsa => rsa.ExportPkcs8PrivateKey(),
            ECDsa ec => ec.ExportPkcs8PrivateKey(),
            _ => throw new NotSupportedException("Unsupported key type")
        };

        return new string(PemEncoding.Write("PRIVATE KEY", pkcs8));
    }

    /// <summary>
    /// Exports the private key of the specified asymmetric algorithm in an encrypted PEM format.
    /// </summary>
    /// <remarks>The private key is encrypted using AES-256-CBC with SHA-256 for hashing and 100,000
    /// iterations. This method ensures the private key is securely exported and suitable for storage or
    /// transfer.</remarks>
    /// <param name="key">The asymmetric algorithm instance containing the private key to export. Must be an instance of <see cref="RSA"/>
    /// or <see cref="ECDsa"/>.</param>
    /// <param name="passphrase">The passphrase used to encrypt the private key. Cannot be null or empty.</param>
    /// <returns>A string containing the encrypted private key in PEM format.</returns>
    /// <exception cref="NotSupportedException">Thrown if the <paramref name="key"/> is not an instance of <see cref="RSA"/> or <see cref="ECDsa"/>.</exception>
    private static string ExportPrivateKeyEncrypted(AsymmetricAlgorithm key, string passphrase)
    {
        var pbe = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100_000);
        byte[] encrypted = key switch
        {
            RSA rsa => rsa.ExportEncryptedPkcs8PrivateKey(Encoding.UTF8.GetBytes(passphrase), pbe),
            ECDsa ec => ec.ExportEncryptedPkcs8PrivateKey(Encoding.UTF8.GetBytes(passphrase), pbe),
            _ => throw new NotSupportedException("Unsupported key type")
        };

        return new string(PemEncoding.Write("ENCRYPTED PRIVATE KEY", encrypted));
    }

    /// <summary>
    /// Exports the public key of the specified asymmetric algorithm to a file in PEM format.
    /// </summary>
    /// <remarks>This method writes the public key in PEM format to the specified file. The caller is
    /// responsible for ensuring that the file path is valid and accessible. The method supports only RSA and ECDsa key
    /// types.</remarks>
    /// <param name="key">The asymmetric algorithm instance containing the public key to export. Must be an instance of <see cref="RSA"/>
    /// or <see cref="ECDsa"/>.</param>
    /// <param name="path">The file path where the PEM-encoded public key will be written. Cannot be null or empty.</param>
    /// <exception cref="NotSupportedException">Thrown if the <paramref name="key"/> is not an instance of <see cref="RSA"/> or <see cref="ECDsa"/>.</exception>
    private static void ExportPublicKey(AsymmetricAlgorithm key, string path)
    {
        byte[] pub = key switch
        {
            RSA rsa => rsa.ExportSubjectPublicKeyInfo(),
            ECDsa ec => ec.ExportSubjectPublicKeyInfo(),
            _ => throw new NotSupportedException("Unsupported key type for public export")
        };

        var pem = new string(PemEncoding.Write("PUBLIC KEY", pub));
        File.WriteAllText(path, pem);
        Log.Information("Exported public key to {Path}", path);
    }

    /// <summary>
    /// Exports the public key from a private PEM file to a specified output file.
    /// </summary>
    /// <remarks>This method reads a private key from a PEM file, extracts the corresponding public key,  and
    /// writes it to a new PEM file. The private key can be encrypted, in which case a passphrase  must be provided.
    /// Supported key formats include RSA and EC.</remarks>
    /// <param name="privateKeyPath">The file path to the private key PEM file. Must be a valid file path.</param>
    /// <param name="passphrase">The passphrase used to decrypt the private key, if it is encrypted.  Can be <see langword="null"/> or empty if
    /// the private key is not encrypted.</param>
    /// <param name="outputPublicKeyPath">The file path where the public key PEM file will be written.</param>
    /// <exception cref="FileNotFoundException">Thrown if the file specified by <paramref name="privateKeyPath"/> does not exist.</exception>
    /// <exception cref="InvalidOperationException">Thrown if the private key format is unsupported or unrecognized.</exception>
    /// <exception cref="NotSupportedException">Thrown if the private key type is unsupported.</exception>
    public static void ExportPublicKeyFromPrivatePem(string privateKeyPath, string? passphrase, string outputPublicKeyPath)
    {
        if (!File.Exists(privateKeyPath))
            throw new FileNotFoundException("Private key file not found.", privateKeyPath);

        var pemText = File.ReadAllText(privateKeyPath);

        AsymmetricAlgorithm key;

        if (pemText.Contains("EC PRIVATE KEY") || pemText.Contains("PRIVATE KEY"))
        {
            var ec = ECDsa.Create();

            if (!string.IsNullOrWhiteSpace(passphrase))
                ec.ImportFromEncryptedPem(pemText, passphrase);
            else
                ec.ImportFromPem(pemText);

            key = ec;
        }
        else if (pemText.Contains("RSA PRIVATE KEY"))
        {
            var rsa = RSA.Create();

            if (!string.IsNullOrWhiteSpace(passphrase))
                rsa.ImportFromEncryptedPem(pemText, passphrase);
            else
                rsa.ImportFromPem(pemText);

            key = rsa;
        }
        else
        {
            throw new InvalidOperationException("Unsupported or unknown key format.");
        }

        byte[] publicBytes = key switch
        {
            RSA rsa => rsa.ExportSubjectPublicKeyInfo(),
            ECDsa ec => ec.ExportSubjectPublicKeyInfo(),
            _ => throw new NotSupportedException("Unsupported key type")
        };

        var pem = new string(PemEncoding.Write("PUBLIC KEY", publicBytes));
        File.WriteAllText(outputPublicKeyPath, pem);

        Log.Information("Exported public key to {OutputPath}", outputPublicKeyPath);
    }

    /// <summary>
    /// Loads a private key from a PEM file and returns the corresponding cryptographic algorithm.
    /// </summary>
    /// <remarks>This method supports loading both EC (Elliptic Curve) and RSA private keys from PEM files.
    /// Ensure the file at <paramref name="path"/> contains a valid PEM-encoded private key.</remarks>
    /// <param name="path">The file path to the PEM file containing the private key.</param>
    /// <param name="passphrase">An optional passphrase used to decrypt the private key if the PEM file is encrypted. If <see langword="null"/>
    /// or empty, the method assumes the PEM file is not encrypted.</param>
    /// <returns>An instance of <see cref="AsymmetricAlgorithm"/> representing the loaded private key. The returned object will
    /// be either an <see cref="ECDsa"/> or <see cref="RSA"/> depending on the key type.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the PEM file contains an unsupported or unrecognized private key format.</exception>
    internal static AsymmetricAlgorithm LoadPrivateKey(string path, string? passphrase)
    {
        var pem = File.ReadAllText(path);

        if (pem.Contains("ENCRYPTED"))
        {
            if (string.IsNullOrWhiteSpace(passphrase))
                throw new InvalidOperationException($"Encrypted PEM at {path}, but no passphrase provided.");

            // Try both RSA and EC, log each attempt
            try
            {
                var rsa = RSA.Create();
                rsa.ImportFromEncryptedPem(pem, passphrase);
                Log.Debug("Loaded encrypted RSA private key from {Path}", path);
                return rsa;
            }
            catch (CryptographicException ex)
            {
                Log.Debug(ex, "RSA ImportFromEncryptedPem failed; attempting EC");
            }

            try
            {
                var ec = ECDsa.Create();
                ec.ImportFromEncryptedPem(pem, passphrase);
                Log.Debug("Loaded encrypted EC private key from {Path}", path);
                return ec;
            }
            catch (CryptographicException ex)
            {
                Log.Debug(ex, "EC ImportFromEncryptedPem failed");
                throw new InvalidOperationException($"Failed to load encrypted private key from {path}. Passphrase may be incorrect or key format unsupported.");
            }
        }

        // Same for unencrypted
        if (pem.Contains("BEGIN EC PRIVATE KEY"))
        {
            var ec = ECDsa.Create();
            ec.ImportFromPem(pem);
            return ec;
        }

        if (pem.Contains("BEGIN RSA PRIVATE KEY") || pem.Contains("BEGIN PRIVATE KEY"))
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(pem);
            return rsa;
        }

        throw new InvalidOperationException("Unsupported or unrecognized PEM key format.");
    }

    private static string GetPublicKeyPath(string privateKeyPath)
    {
        if (privateKeyPath.EndsWith(".pem", StringComparison.OrdinalIgnoreCase))
            return privateKeyPath.Substring(0, privateKeyPath.Length - 4) + ".pub.pem";

        return privateKeyPath + ".pub.pem";
    }

    public static string GenerateKeyIdFromPublicKey(AsymmetricAlgorithm key)
    {
        byte[] pub = key switch
        {
            RSA rsa => rsa.ExportSubjectPublicKeyInfo(),
            ECDsa ec => ec.ExportSubjectPublicKeyInfo(),
            _ => throw new NotSupportedException("Unsupported key type")
        };

        using var sha = SHA256.Create();
        var hash = sha.ComputeHash(pub);
        return Convert.ToBase64String(hash)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_'); // URL-safe
    }
}
