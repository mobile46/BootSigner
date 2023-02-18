using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.IO;
using System.Linq;
using System.Text;

namespace BootSigner
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            if (args[0] == "-verify")
            {
                var str = string.Empty;
                if (args.Length >= 4 && args[2] == "-certificate")
                    str = args[3];
                BootSignature.VerifySignature(args[1], str);
                return;
            }
            BootSignature.DoSignature(args[0], args[1], args[2], args[3], args[4]);
        }
    }

    internal class BootSignature : Asn1Encodable
    {
        private readonly DerInteger _formatVersion;
        private Asn1Encodable _certificate;
        private AlgorithmIdentifier _algorithmIdentifier;
        private readonly DerPrintableString _target;
        private readonly DerInteger _length;
        private DerOctetString _signature;
        private AsymmetricKeyParameter _publicKey;

        private const int FormatVersion = 1;
        private const int BootImageHeaderV1RecoveryDtboSizeOffset = 1632;
        private const int BootImageHeaderV2DtbSizeOffset = 1648;
        private const int BootImageHeaderVersionMaximum = 8;

        public BootSignature(string target, int length)
        {
            _formatVersion = new DerInteger(FormatVersion);
            _target = new DerPrintableString(target);
            _length = new DerInteger(length);
        }

        public BootSignature(byte[] signature)
        {
            var stream = new Asn1InputStream(signature);
            var sequence = (Asn1Sequence)stream.ReadObject();

            _formatVersion = (DerInteger)sequence[0];
            if (_formatVersion.Value.IntValue != FormatVersion)
                throw new Exception("Unsupported format version");

            _certificate = sequence[1];
            var encoded = ((Asn1Object)_certificate).GetEncoded();
            var c = CryptoUtils.ReadCertificate(encoded);
            _publicKey = c.GetPublicKey();

            var algId = (Asn1Sequence)sequence[2];
            _algorithmIdentifier = new AlgorithmIdentifier((DerObjectIdentifier)algId[0]);

            var attrs = (Asn1Sequence)sequence[3];
            _target = (DerPrintableString)attrs[0];
            _length = (DerInteger)attrs[1];

            _signature = (DerOctetString)sequence[4];
        }

        public Asn1Object GetAuthenticatedAttributes()
        {
            return new DerSequence(new Asn1EncodableVector
            {
                _target,
                _length
            });
        }

        public byte[] GetEncodedAuthenticatedAttributes()
        {
            return GetAuthenticatedAttributes().GetEncoded();
        }

        public void SetSignature(byte[] sig, AlgorithmIdentifier algId)
        {
            _algorithmIdentifier = algId;
            _signature = new DerOctetString(sig);
        }

        public void SetCertificate(X509Certificate cert)
        {
            _certificate = new Asn1InputStream(cert.GetEncoded()).ReadObject();
            _publicKey = cert.GetPublicKey();
        }

        public byte[] GenerateSignableImage(byte[] image)
        {
            var attrs = GetEncodedAuthenticatedAttributes();
            var signable = new byte[image.Length + attrs.Length];
            Array.Copy(image, signable, image.Length);
            for (var i = 0; i < attrs.Length; i++)
            {
                signable[i + image.Length] = attrs[i];
            }
            return signable;
        }

        public byte[] Sign(byte[] image, AsymmetricKeyParameter privateKey)
        {
            var array = GenerateSignableImage(image);
            var signer = SignerUtilities.GetSigner(CryptoUtils.DefaultAlgorithmIdentifier);
            signer.Init(true, privateKey);
            signer.BlockUpdate(array, 0, array.Length);
            return signer.GenerateSignature();
        }

        public bool Verify(byte[] image)
        {
            if (_length.Value.IntValue != image.Length)
                throw new Exception("Invalid image length");

            var array = GenerateSignableImage(image);
            var signer = SignerUtilities.GetSigner(CryptoUtils.DefaultAlgorithmIdentifier);
            signer.Init(false, _publicKey);
            signer.BlockUpdate(array, 0, array.Length);
            return signer.VerifySignature(_signature.GetOctets());
        }

        public override Asn1Object ToAsn1Object()
        {
            return new DerSequence(new Asn1EncodableVector
            {
                _formatVersion,
                _certificate,
                _algorithmIdentifier,
                GetAuthenticatedAttributes(),
                _signature
            });
        }

        public static int GetSignableImageSize(byte[] data)
        {
            var buffer = new byte[8];
            Array.Copy(data, buffer, buffer.Length);
            if (!buffer.SequenceEqual(Encoding.ASCII.GetBytes("ANDROID!")))
                throw new Exception("Invalid image header: missing magic");

            var image = new BinaryReader(new MemoryStream(data));
            image.ReadInt64(); // magic
            var kernelSize = image.ReadInt32();
            image.ReadInt32(); // kernel_addr
            var ramdskSize = image.ReadInt32();
            image.ReadInt32(); // ramdisk_addr
            var secondSize = image.ReadInt32();
            image.ReadInt64(); // second_addr + tags_addr
            var pageSize = image.ReadInt32();
            if (pageSize >= 0x02000000)
                throw new Exception("Invalid image header: PXA header detected");

            var length = pageSize // include the page aligned image header
                         + (kernelSize + pageSize - 1) / pageSize * pageSize
                         + (ramdskSize + pageSize - 1) / pageSize * pageSize
                         + (secondSize + pageSize - 1) / pageSize * pageSize;
            var headerVersion = image.ReadInt32(); // boot image header version or dt/extra size
            if (headerVersion > 0 && headerVersion < BootImageHeaderVersionMaximum)
            {
                image.BaseStream.Position = BootImageHeaderV1RecoveryDtboSizeOffset;
                var recoveryDtboLength = image.ReadInt32();
                length += (recoveryDtboLength + pageSize - 1) / pageSize * pageSize;
                image.ReadInt64(); // recovery_dtbo address
                var headerSize = image.ReadInt32();
                if (headerVersion == 2)
                {
                    image.BaseStream.Position = BootImageHeaderV2DtbSizeOffset;
                    var dtbLength = image.ReadInt32();
                    length += (dtbLength + pageSize - 1) / pageSize * pageSize;
                    image.ReadInt64(); // dtb address
                }
                if (image.BaseStream.Position != headerSize)
                    throw new Exception("Invalid image header: invalid header length");
            }
            else
                length += (headerVersion + pageSize - 1) / pageSize * pageSize;

            length = (length + pageSize - 1) / pageSize * pageSize;
            if (length <= 0)
                throw new Exception("Invalid image header: invalid length");
            return length;
        }

        public static void DoSignature(string target, string imagePath, string keyPath, string certPath, string outPath)
        {
            var image = File.ReadAllBytes(imagePath);
            var signableSize = GetSignableImageSize(image);
            if (signableSize < image.Length)
            {
                Console.WriteLine($"NOTE: truncating file {imagePath} from {image.Length} to {signableSize} bytes");
                Array.Resize(ref image, signableSize);
            }
            else if (signableSize > image.Length)
                throw new Exception($"Invalid image: too short, expected {signableSize} bytes");

            var bootsig = new BootSignature(target, image.Length);
            var cert = CryptoUtils.ReadCertificate(certPath);
            bootsig.SetCertificate(cert);
            var key = CryptoUtils.ReadPrivateKey(keyPath);
            bootsig.SetSignature(bootsig.Sign(image, key), CryptoUtils.GetSignatureAlgorithmIdentifier());
            var encodedBootsig = bootsig.GetEncoded();
            var imageWithMetadata = new byte[image.Length + encodedBootsig.Length];
            Array.Copy(image, imageWithMetadata, image.Length);
            Array.Copy(encodedBootsig, 0, imageWithMetadata, image.Length, encodedBootsig.Length);
            File.WriteAllBytes(outPath, imageWithMetadata);
        }

        public static void VerifySignature(string imagePath, string certPath)
        {
            var image = File.ReadAllBytes(imagePath);
            var signableSize = GetSignableImageSize(image);

            if (signableSize >= image.Length)
                throw new Exception("Invalid image: not signed");

            var signature = new byte[image.Length - signableSize];
            Array.Copy(image, signableSize, signature, 0, image.Length - signableSize);

            var bootsig = new BootSignature(signature);

            if (!string.IsNullOrEmpty(certPath))
            {
                Console.WriteLine($"NOTE: verifying using public key from {certPath}");
                bootsig.SetCertificate(CryptoUtils.ReadCertificate(certPath));
            }

            try
            {
                var buffer = new byte[signableSize];
                Array.Copy(image, buffer, buffer.Length);
                if (bootsig.Verify(buffer))
                {
                    Console.WriteLine("Signature is VALID");
                    Environment.Exit(0);
                }
                else
                {
                    Console.WriteLine("Signature is INVALID");
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
            Environment.Exit(1);
        }
    }

    public class CryptoUtils
    {
        public static DerObjectIdentifier DefaultAlgorithmIdentifier = PkcsObjectIdentifiers.Sha256WithRsaEncryption;

        public static AlgorithmIdentifier GetSignatureAlgorithmIdentifier()
        {
            return new AlgorithmIdentifier(DefaultAlgorithmIdentifier, DerNull.Instance);
        }

        public static X509Certificate ReadCertificate(byte[] array)
        {
            return new X509CertificateParser().ReadCertificate(array);
        }

        public static X509Certificate ReadCertificate(string path)
        {
            return ReadCertificate(File.ReadAllBytes(path));
        }

        public static AsymmetricKeyParameter ReadPrivateKey(string path)
        {
            return PrivateKeyFactory.CreateKey(PrivateKeyInfo.GetInstance(Asn1Object.FromByteArray(File.ReadAllBytes(path))));
        }
    }
}