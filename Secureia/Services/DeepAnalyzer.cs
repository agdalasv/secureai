using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Secureia.Models;

namespace Secureia.Services;

public class DeepAnalyzer
{
    private readonly DefinitionService? _defService;
    private readonly ThreatDatabase? _threatDb;
    private readonly string _tempDir;

    private static readonly byte[] PngIendMarker = { 0x49, 0x45, 0x4E, 0x44 };
    private static readonly byte[] JpegEoiMarker = { 0xFF, 0xD9 };
    private static readonly byte[] GifTrailer = { 0x3B };

    private static readonly string[] ScriptInjectionPatterns =
    {
        "powershell", "Invoke-Expression", "IEX(", "Invoke-WebRequest",
        "Start-Process", "New-Object Net.WebClient", "DownloadString",
        "DownloadFile", "FromBase64String", "ShellExecute",
        "WScript.Shell", "Shell.Application", "ActiveXObject",
        "eval(", "document.write", "unescape(", "String.fromCharCode",
        "base64_decode", "gzinflate", "str_rot13", "preg_replace",
        "CreateObject", "WinHttp.WinHttpRequest", "MSXML2.XMLHTTP",
        "ADODB.Stream", "WMI", "GetObject", "ExecQuery"
    };

    private static readonly byte[][] KnownMalwareSignatures =
    {
        Encoding.ASCII.GetBytes("This program cannot be run in DOS mode"),
        // Common shellcode NOP sled patterns
        new byte[] { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 },
        new byte[] { 0xEB, 0xFE }, // JMP $ infinite loop
        // Common XOR decoder stub pattern
        new byte[] { 0x33, 0xC9, 0x33, 0xD2, 0x8A, 0x06, 0x34, 0xAA },
        // Known malware byte sequences
        Encoding.ASCII.GetBytes("MZ"),
        // Zeus/Gameover pattern
        new byte[] { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x59, 0x8B, 0xF1 }
    };

    public DeepAnalyzer(DefinitionService? defService = null, ThreatDatabase? threatDb = null)
    {
        _defService = defService;
        _threatDb = threatDb;
        _tempDir = Path.Combine(Path.GetTempPath(), "SecureAI_DeepScan");
        Directory.CreateDirectory(_tempDir);
    }

    public List<ScanResult> AnalyzeDeep(string filePath)
    {
        var results = new List<ScanResult>();
        try
        {
            if (!File.Exists(filePath)) return results;

            var fi = new FileInfo(filePath);
            if (fi.Length > 500 * 1024 * 1024) return results;

            var extension = Path.GetExtension(filePath).ToLowerInvariant();

            switch (extension)
            {
                case ".zip":
                    results.AddRange(AnalyzeZipArchive(filePath));
                    break;
                case ".exe":
                case ".dll":
                case ".scr":
                case ".ocx":
                case ".cpl":
                    results.AddRange(AnalyzePeFile(filePath));
                    break;
                case ".txt":
                case ".html":
                case ".htm":
                case ".js":
                case ".vbs":
                case ".ps1":
                case ".bat":
                case ".cmd":
                case ".xml":
                case ".hta":
                    results.AddRange(AnalyzeTextFile(filePath));
                    break;
                case ".png":
                case ".jpg":
                case ".jpeg":
                case ".gif":
                case ".bmp":
                    results.AddRange(AnalyzeImageFile(filePath));
                    break;
                default:
                    results.AddRange(AnalyzeBinaryFile(filePath));
                    break;
            }
        }
        catch { }
        return results;
    }

    private List<ScanResult> AnalyzeZipArchive(string filePath)
    {
        var results = new List<ScanResult>();
        try
        {
            using var archive = ZipFile.OpenRead(filePath);
            long totalUncompressed = 0;
            int fileCount = 0;
            var suspiciousEntries = new List<string>();

            foreach (var entry in archive.Entries)
            {
                totalUncompressed += entry.Length;
                fileCount++;

                var name = entry.Name.ToLowerInvariant();
                if (string.IsNullOrEmpty(name)) continue;

                if (name.EndsWith(".exe") || name.EndsWith(".scr") || name.EndsWith(".ps1"))
                    suspiciousEntries.Add($"{name} (ejecutable dentro de archivo)");

                if (name.Contains("..\\") || name.Contains("../../") || name.Contains("..\\\\"))
                    suspiciousEntries.Add($"{name} (path traversal en archivo)");

                if (entry.Length > 100 * 1024 * 1024)
                    suspiciousEntries.Add($"{name} ({entry.Length} bytes - archivo sospechosamente grande)");

                if (entry.CompressedLength > 0 && entry.Length > 0)
                {
                    var ratio = (double)entry.Length / entry.CompressedLength;
                    if (ratio > 100)
                        suspiciousEntries.Add($"{name} (alta compresión {ratio:F0}x - posible zip bomb)");
                }
            }

            if (fileCount > 1000)
                suspiciousEntries.Add($"{fileCount} archivos en el ZIP - cantidad sospechosa");

            if (suspiciousEntries.Count > 0)
            {
                results.Add(new ScanResult
                {
                    FilePath = filePath,
                    ThreatName = string.Join("; ", suspiciousEntries.Take(5)),
                    Level = ThreatLevel.Medium,
                    Description = $"Archivo comprimido sospechoso: {string.Join(", ", suspiciousEntries.Take(3))}",
                    DetectedAt = DateTime.Now
                });
            }
        }
        catch { }
        return results;
    }

    private List<ScanResult> AnalyzePeFile(string filePath)
    {
        var results = new List<ScanResult>();
        try
        {
            using var stream = File.OpenRead(filePath);
            using var reader = new BinaryReader(stream);

            if (stream.Length < 64) return results;

            stream.Seek(0, SeekOrigin.Begin);
            var dosMagic = reader.ReadUInt16();
            if (dosMagic != 0x5A4D) return results;

            stream.Seek(0x3C, SeekOrigin.Begin);
            var peOffset = reader.ReadInt32();
            if (peOffset < 64 || peOffset > stream.Length - 4) return results;

            stream.Seek(peOffset, SeekOrigin.Begin);
            var peMagic = reader.ReadUInt32();
            if (peMagic != 0x00004550) return results;

            var machine = reader.ReadUInt16();
            var numberOfSections = reader.ReadUInt16();
            var timestamp = reader.ReadUInt32();
            reader.ReadBytes(16);
            var sizeOfOptionalHeader = reader.ReadUInt16();
            var characteristics = reader.ReadUInt16();

            var threats = new List<string>();

            var entryPoint = 0u;

            stream.Seek(peOffset + 24, SeekOrigin.Begin);
            var magic = reader.ReadUInt16();

            if (magic == 0x10B || magic == 0x20B)
            {
                stream.Seek(peOffset + 24, SeekOrigin.Begin);
                reader.ReadBytes(8);
                entryPoint = reader.ReadUInt32();
                if (magic == 0x10B)
                {
                }
                else
                {
                    reader.ReadBytes(4);
                }
            }

            if (entryPoint < 0x1000 && ((Characteristics)characteristics).HasFlag(Characteristics.Dll))
                threats.Add("[PE] Entry point in first page - posible EPO/rootkit");

            stream.Seek(peOffset + 24 + sizeOfOptionalHeader, SeekOrigin.Begin);

            var suspiciousSectionNames = new[] { ".xyz", ".foo", ".bar", ".hack", ".pck", ".zdata", ".mackt" };
            var sectionThreats = new List<string>();
            var highEntropySections = new List<string>();

            for (int i = 0; i < numberOfSections && i < 100; i++)
            {
                if (stream.Position + 40 > stream.Length) break;
                var nameBytes = reader.ReadBytes(8);
                var sectionName = Encoding.ASCII.GetString(nameBytes).TrimEnd('\0');
                var virtualSize = reader.ReadUInt32();
                var virtualAddress = reader.ReadUInt32();
                var rawSize = reader.ReadUInt32();
                var rawPtr = reader.ReadUInt32();
                reader.ReadBytes(12);
                var sectionCharacteristics = reader.ReadUInt32();

                if (string.IsNullOrEmpty(sectionName)) continue;

                if (suspiciousSectionNames.Contains(sectionName, StringComparer.OrdinalIgnoreCase))
                    sectionThreats.Add($"sección '{sectionName}'");

                var isExecutable = (sectionCharacteristics & 0x20000000) != 0;
                var isWritable = (sectionCharacteristics & 0x80000000) != 0;
                if (isExecutable && isWritable && i > 0)
                    sectionThreats.Add($"sección '{sectionName}' (RWX)");

                if (rawSize > 0 && rawPtr > 0 && rawPtr + rawSize <= stream.Length)
                {
                    var pos = stream.Position;
                    stream.Seek(rawPtr, SeekOrigin.Begin);
                    var sectionData = reader.ReadBytes((int)Math.Min(rawSize, 1024 * 1024));
                    stream.Seek(pos, SeekOrigin.Begin);

                    var entropy = CalculateEntropy(sectionData);
                    if (entropy > 7.0 && i > 0)
                        highEntropySections.Add($"sección '{sectionName}' (entropía {entropy:F2})");
                }
            }

            if (sectionThreats.Count > 0)
                threats.Add($"[PE] Secciones anómalas: {string.Join(", ", sectionThreats)}");

            if (highEntropySections.Count >= 2)
                threats.Add($"[PE] Múltiples secciones con alta entropía: {string.Join(", ", highEntropySections)}");

            if (entryPoint == 0 && ((Characteristics)characteristics).HasFlag(Characteristics.ExecutableImage))
                threats.Add("[PE] Entry point cero con características ejecutable - posible infección");

            stream.Seek(peOffset + 24 + sizeOfOptionalHeader + numberOfSections * 40, SeekOrigin.Begin);

            if (threats.Count > 0)
            {
                results.Add(new ScanResult
                {
                    FilePath = filePath,
                    ThreatName = string.Join("; ", threats),
                    Level = ThreatLevel.Medium,
                    Description = $"Análisis PE: {string.Join(", ", threats)}",
                    DetectedAt = DateTime.Now
                });
            }

            var importResults = ScanImports(stream, reader, filePath);
            results.AddRange(importResults);
        }
        catch { }
        return results;
    }

    [Flags]
    private enum Characteristics : ushort
    {
        RelocsStripped = 0x0001,
        ExecutableImage = 0x0002,
        LineNumsStripped = 0x0004,
        LocalSymsStripped = 0x0008,
        AggressiveWsTrim = 0x0010,
        LargeAddressAware = 0x0020,
        BytesReservedLo = 0x0080,
        Machine32Bit = 0x0100,
        DebugStripped = 0x0200,
        RemovableRunFromSwap = 0x0400,
        NetRunFromSwap = 0x0800,
        System = 0x1000,
        Dll = 0x2000,
        UpSystemOnly = 0x4000,
        BytesReservedHi = 0x8000
    }

    private List<ScanResult> ScanImports(System.IO.Stream stream, System.IO.BinaryReader reader, string filePath)
    {
        var results = new List<ScanResult>();
        return results;
    }

    private static double CalculateEntropy(byte[] data)
    {
        if (data.Length == 0) return 0;
        var freq = new int[256];
        foreach (var b in data)
            freq[b]++;

        double entropy = 0;
        var len = data.Length;
        for (int i = 0; i < 256; i++)
        {
            if (freq[i] == 0) continue;
            double p = (double)freq[i] / len;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    private List<ScanResult> AnalyzeTextFile(string filePath)
    {
        var results = new List<ScanResult>();
        try
        {
            var content = File.ReadAllText(filePath, Encoding.UTF8);
            if (string.IsNullOrEmpty(content) || content.Length < 20) return results;

            var threats = new List<string>();
            var lowContentLength = content.Length < 50;
            if (lowContentLength) return results;

            var detectedPatterns = ScriptInjectionPatterns
                .Where(p => content.IndexOf(p, StringComparison.OrdinalIgnoreCase) >= 0)
                .ToList();

            if (detectedPatterns.Count >= 3)
                threats.Add($"[Script] Patrones de inyección detectados: {string.Join(", ", detectedPatterns.Take(5))}");

            if (detectedPatterns.Count >= 5)
                threats.Add("[Script] Múltiples técnicas de inyección combinadas");

            var base64Count = CountBase64Strings(content);
            if (base64Count > 3)
                threats.Add($"[Script] {base64Count} cadenas Base64 largas (posible payload ofuscado)");

            var obfuscationIndicators = CountObfuscationIndicators(content);
            if (obfuscationIndicators >= 3)
                threats.Add("[Script] Técnicas de ofuscación detectadas");

            if (content.Contains("FromBase64String", StringComparison.OrdinalIgnoreCase) &&
                (content.Contains("DownloadString", StringComparison.OrdinalIgnoreCase) ||
                 content.Contains("DownloadFile", StringComparison.OrdinalIgnoreCase)))
                threats.Add("[Script] Payload remoto: Base64 combinado con descarga");

            if (content.Contains("Invoke-Expression", StringComparison.OrdinalIgnoreCase) ||
                content.Contains("IEX(", StringComparison.OrdinalIgnoreCase))
            {
                var iexLine = content.Split('\n').FirstOrDefault(l =>
                    l.Contains("IEX(", StringComparison.OrdinalIgnoreCase) ||
                    l.Contains("Invoke-Expression", StringComparison.OrdinalIgnoreCase));
                if (iexLine != null && iexLine.Length > 50)
                    threats.Add("[Script] IEX con payload largo - posible descarga y ejecución");
            }

            var urlPattern = @"https?:\/\/(?:[^\s\/\"")]+\.)+[^\s\/\"")]+(?:\/[^\s\/\"")]*)*\.(?:exe|ps1|vbs|bat|dll|scr)";
            if (System.Text.RegularExpressions.Regex.IsMatch(content, urlPattern, System.Text.RegularExpressions.RegexOptions.IgnoreCase))
                threats.Add("[Script] URL de descarga de ejecutable sospechoso");

            if (threats.Count > 0)
            {
                results.Add(new ScanResult
                {
                    FilePath = filePath,
                    ThreatName = string.Join("; ", threats),
                    Level = threats.Count >= 3 ? ThreatLevel.Medium : ThreatLevel.Low,
                    Description = $"Análisis de script/texto: {string.Join(", ", threats)}",
                    DetectedAt = DateTime.Now
                });
            }
        }
        catch { }
        return results;
    }

    private static int CountBase64Strings(string content)
    {
        int count = 0;
        var matches = System.Text.RegularExpressions.Regex.Matches(content,
            @"[A-Za-z0-9+/]{40,}={0,2}");
        foreach (System.Text.RegularExpressions.Match m in matches)
        {
            if (m.Length >= 40)
                count++;
        }
        return count;
    }

    private static int CountObfuscationIndicators(string content)
    {
        int count = 0;
        if (content.Contains("char(", StringComparison.OrdinalIgnoreCase) ||
            content.Contains("Chr(", StringComparison.OrdinalIgnoreCase))
            count++;
        if (content.Contains("Split", StringComparison.OrdinalIgnoreCase) &&
            (content.Contains("join", StringComparison.OrdinalIgnoreCase) ||
             content.Contains("concat", StringComparison.OrdinalIgnoreCase)))
            count++;
        if (System.Text.RegularExpressions.Regex.IsMatch(content, @"\\x[0-9a-fA-F]{2}"))
            count++;
        if (System.Text.RegularExpressions.Regex.IsMatch(content, @"\\u[0-9a-fA-F]{4}"))
            count++;
        if (content.Contains("Replace", StringComparison.OrdinalIgnoreCase) &&
            content.Contains("(") && content.Contains(")"))
        {
            var replaceCount = System.Text.RegularExpressions.Regex.Matches(content,
                @"\.Replace\(", System.Text.RegularExpressions.RegexOptions.IgnoreCase).Count;
            if (replaceCount >= 3) count++;
        }
        if (content.Contains("eval(", StringComparison.OrdinalIgnoreCase))
            count++;
        if (content.Contains("exec(", StringComparison.OrdinalIgnoreCase))
            count++;
        return count;
    }

    private List<ScanResult> AnalyzeImageFile(string filePath)
    {
        var results = new List<ScanResult>();
        try
        {
            using var stream = File.OpenRead(filePath);
            if (stream.Length < 50) return results;

            var extension = Path.GetExtension(filePath).ToLowerInvariant();
            var buffer = new byte[Math.Min(stream.Length, 1024 * 1024)];
            stream.Read(buffer, 0, buffer.Length);

            var threats = new List<string>();

            if (extension == ".png")
            {
                var iendPos = FindLastPattern(buffer, PngIendMarker);
                if (iendPos >= 0)
                {
                    var afterIend = buffer.Length - iendPos - PngIendMarker.Length - 4;
                    if (afterIend > 100)
                        threats.Add($"[Imagen] {afterIend} bytes después del marcador IEND en PNG (posible dato oculto)");
                }
            }
            else if (extension == ".jpg" || extension == ".jpeg")
            {
                var eoiPos = FindLastPattern(buffer, JpegEoiMarker);
                if (eoiPos >= 0)
                {
                    var afterEoi = buffer.Length - eoiPos - JpegEoiMarker.Length;
                    if (afterEoi > 100)
                        threats.Add($"[Imagen] {afterEoi} bytes después del marcador EOI en JPEG (posible dato oculto)");
                }

                var exifCount = CountOccurrences(buffer, Encoding.ASCII.GetBytes("Exif"));
                if (exifCount > 3)
                    threats.Add("[Imagen] Múltiples bloques EXIF - posible esteganografía");
            }
            else if (extension == ".gif")
            {
                var trailerPos = FindLastPattern(buffer, GifTrailer);
                if (trailerPos >= 0)
                {
                    var afterTrailer = buffer.Length - trailerPos - GifTrailer.Length;
                    if (afterTrailer > 100)
                        threats.Add($"[Imagen] {afterTrailer} bytes después del trailer GIF (posible dato oculto)");
                }
            }

            if (extension == ".bmp")
            {
                var bmpDataSize = BitConverter.ToInt32(buffer, 2);
                if (bmpDataSize > stream.Length * 1.5)
                    threats.Add("[Imagen] BMP con tamaño de datos inconsistente - posible esteganografía");
            }

            var entropy = CalculateEntropy(buffer);
            if (entropy > 7.8 && stream.Length > 10000)
                threats.Add($"[Imagen] Entropía alta ({entropy:F2}) en datos de imagen - posible dato cifrado embebido");

            if (threats.Count > 0)
            {
                results.Add(new ScanResult
                {
                    FilePath = filePath,
                    ThreatName = string.Join("; ", threats),
                    Level = ThreatLevel.Low,
                    Description = $"Análisis de imagen: {string.Join(", ", threats)}",
                    DetectedAt = DateTime.Now
                });
            }
        }
        catch { }
        return results;
    }

    private List<ScanResult> AnalyzeBinaryFile(string filePath)
    {
        var results = new List<ScanResult>();
        try
        {
            using var stream = File.OpenRead(filePath);
            if (stream.Length < 64) return results;

            var extension = Path.GetExtension(filePath).ToLowerInvariant();
            if (extension == ".exe" || extension == ".dll" || extension == ".scr" ||
                extension == ".zip" || extension == ".rar" || extension == ".7z" ||
                extension == ".png" || extension == ".jpg" || extension == ".jpeg" ||
                extension == ".gif" || extension == ".txt" || extension == ".html" ||
                extension == ".htm" || extension == ".js" || extension == ".vbs" ||
                extension == ".ps1" || extension == ".bat" || extension == ".cmd")
                return results;

            var buffer = new byte[Math.Min(stream.Length, 64 * 1024)];
            stream.Read(buffer, 0, buffer.Length);

            var threats = new List<string>();

            for (int i = 0; i < KnownMalwareSignatures.Length; i++)
            {
                if (ContainsPattern(buffer, KnownMalwareSignatures[i]))
                {
                    threats.Add($"[Binario] Firma de malware conocida detectada (patrón {i + 1})");
                    break;
                }
            }

            if (stream.Length >= 512)
            {
                var sample2 = new byte[Math.Min(stream.Length - 256, 4096)];
                stream.Seek(stream.Length - sample2.Length, SeekOrigin.Begin);
                stream.Read(sample2, 0, sample2.Length);

                for (int i = 0; i < KnownMalwareSignatures.Length; i++)
                {
                    if (ContainsPattern(sample2, KnownMalwareSignatures[i]))
                    {
                        threats.Add($"[Binario] Firma de malware al final del archivo (patrón {i + 1})");
                        break;
                    }
                }
            }

            var entropy = CalculateEntropy(buffer);
            if (entropy > 7.5 && stream.Length > 4096)
                threats.Add($"[Binario] Alta entropía ({entropy:F2}) - posible contenido cifrado/comprimido");

            if (threats.Count > 0)
            {
                results.Add(new ScanResult
                {
                    FilePath = filePath,
                    ThreatName = string.Join("; ", threats),
                    Level = ThreatLevel.Medium,
                    Description = $"Análisis binario: {string.Join(", ", threats)}",
                    DetectedAt = DateTime.Now
                });
            }
        }
        catch { }
        return results;
    }

    private static int FindLastPattern(byte[] data, byte[] pattern)
    {
        for (int i = data.Length - pattern.Length; i >= 0; i--)
        {
            bool match = true;
            for (int j = 0; j < pattern.Length; j++)
            {
                if (data[i + j] != pattern[j]) { match = false; break; }
            }
            if (match) return i;
        }
        return -1;
    }

    private static int CountOccurrences(byte[] data, byte[] pattern)
    {
        int count = 0;
        for (int i = 0; i <= data.Length - pattern.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < pattern.Length; j++)
            {
                if (data[i + j] != pattern[j]) { match = false; break; }
            }
            if (match) count++;
        }
        return count;
    }

    private static bool ContainsPattern(byte[] data, byte[] pattern)
    {
        return FindLastPattern(data, pattern) >= 0;
    }
}
