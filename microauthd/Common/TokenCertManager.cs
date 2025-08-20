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
    /// Exports the public key from a private key PEM file and writes it to a specified output file.
    /// </summary>
    /// <remarks>This method supports both RSA and EC private keys. If the private key PEM file is encrypted, 
    /// the provided <paramref name="passphrase"/> will be used to decrypt it. The public key is exported  in the
    /// Subject Public Key Info (SPKI) format and written to the specified output file in PEM encoding.</remarks>
    /// <param name="privateKeyPath">The file path to the private key PEM file. The file must exist.</param>
    /// <param name="passphrase">The passphrase used to decrypt the private key, if the PEM file is encrypted.  Specify <see langword="null"/> or
    /// an empty string if the private key is not encrypted.</param>
    /// <param name="outputPublicKeyPath">The file path where the exported public key will be written.</param>
    /// <exception cref="FileNotFoundException">Thrown if the file specified by <paramref name="privateKeyPath"/> does not exist.</exception>
    /// <exception cref="NotSupportedException">Thrown if the private key type is unsupported.</exception>
    public static void ExportPublicKeyFromPrivatePem(string privateKeyPath, string? passphrase, string outputPublicKeyPath)
    {
        if (!File.Exists(privateKeyPath))
            throw new FileNotFoundException("Private key file not found.", privateKeyPath);

        var pem = File.ReadAllText(privateKeyPath);

        AsymmetricAlgorithm key;
        if (pem.Contains("ENCRYPTED"))
        {
            // Try RSA then EC
            try { var rsa = RSA.Create(); rsa.ImportFromEncryptedPem(pem, passphrase ?? ""); key = rsa; }
            catch
            {
                var ec = ECDsa.Create(); ec.ImportFromEncryptedPem(pem, passphrase ?? "");
                key = ec;
            }
        }
        else
        {
            // Try RSA then EC
            try { var rsa = RSA.Create(); rsa.ImportFromPem(pem); key = rsa; }
            catch
            {
                var ec = ECDsa.Create(); ec.ImportFromPem(pem);
                key = ec;
            }
        }

        byte[] spki = key switch
        {
            RSA rsa => rsa.ExportSubjectPublicKeyInfo(),
            ECDsa ec => ec.ExportSubjectPublicKeyInfo(),
            _ => throw new NotSupportedException("Unsupported key type")
        };

        File.WriteAllText(outputPublicKeyPath, new string(System.Security.Cryptography.PemEncoding.Write("PUBLIC KEY", spki)));
    }

    /// <summary>
    /// Loads a private key from a PEM file and returns the corresponding asymmetric algorithm instance.
    /// </summary>
    /// <remarks>This method attempts to load the private key as either an RSA or ECDsa key. If the key is
    /// encrypted,  the provided <paramref name="passphrase"/> is used to decrypt it. If the key is unencrypted, the 
    /// passphrase is ignored. <para> The method throws an exception if the key format is unsupported, unrecognized, or
    /// if the passphrase  is incorrect for an encrypted key. </para></remarks>
    /// <param name="path">The file path to the PEM-encoded private key.</param>
    /// <param name="passphrase">The passphrase used to decrypt the private key, if the key is encrypted.  Specify <see langword="null"/> or an
    /// empty string for unencrypted keys.</param>
    /// <returns>An instance of <see cref="RSA"/> or <see cref="ECDsa"/> representing the loaded private key.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the private key cannot be loaded due to an unsupported format, unrecognized PEM structure,  or
    /// incorrect passphrase.</exception>
    internal static AsymmetricAlgorithm LoadPrivateKey(string path, string? passphrase)
    {
        var pem = File.ReadAllText(path);

        // Encrypted?
        if (pem.Contains("ENCRYPTED"))
        {
            // Try RSA first
            try { var rsa = RSA.Create(); rsa.ImportFromEncryptedPem(pem, passphrase ?? ""); return rsa; } catch { }
            // Then EC
            try { var ec = ECDsa.Create(); ec.ImportFromEncryptedPem(pem, passphrase ?? ""); return ec; } catch { }
            throw new InvalidOperationException($"Failed to load encrypted private key from {path}. Passphrase wrong or format unsupported.");
        }

        // Unencrypted: try RSA, then EC
        try { var rsa = RSA.Create(); rsa.ImportFromPem(pem); return rsa; } catch { }
        try { var ec = ECDsa.Create(); ec.ImportFromPem(pem); return ec; } catch { }

        throw new InvalidOperationException("Unsupported or unrecognized PEM key format.");
    }

    private static string GetPublicKeyPath(string privateKeyPath)
    {
        if (privateKeyPath.EndsWith(".pem", StringComparison.OrdinalIgnoreCase))
            return privateKeyPath.Substring(0, privateKeyPath.Length - 4) + ".pub.pem";

        return privateKeyPath + ".pub.pem";
    }

    /// <summary>
    /// Generates a URL-safe key identifier from the public key of the specified asymmetric algorithm.
    /// </summary>
    /// <remarks>This method computes a unique identifier for the public key by exporting the key in the
    /// SubjectPublicKeyInfo format, hashing it using SHA-256, and encoding the hash in a URL-safe Base64 format. The
    /// resulting identifier can be used in scenarios such as key management or cryptographic operations.</remarks>
    /// <param name="key">The asymmetric algorithm containing the public key. Supported types are <see cref="RSA"/> and <see
    /// cref="ECDsa"/>.</param>
    /// <returns>A URL-safe, Base64-encoded string representing the SHA-256 hash of the public key.</returns>
    /// <exception cref="NotSupportedException">Thrown if the <paramref name="key"/> is not of a supported type (<see cref="RSA"/> or <see cref="ECDsa"/>).</exception>
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
