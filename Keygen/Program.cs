using System.Security.Cryptography;
using System.Text;

const string ValidChars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const int GroupSize = 5;
const int RawLength = 25;

byte[] SecretKey = Encoding.UTF8.GetBytes("S3cur3AI-P1us-2K26-K3y!@#");

Console.ForegroundColor = ConsoleColor.Cyan;
Console.WriteLine(@"
  ███████  ██████  ██    ██ ██████  ███████  █████  ██
  ██      ██       ██  ██  ██   ██ ██      ██   ██ ██
  ███████ ██        ████   ██████  █████   ███████ ██
       ██ ██        ██     ██   ██ ██      ██   ██ ██
  ███████  ██████   ██     ██   ██ ███████ ██   ██ ███████
");
Console.ResetColor();
Console.WriteLine("=== Secure AI Plus - Generador de Licencias ===");
Console.WriteLine();

while (true)
{
    Console.ForegroundColor = ConsoleColor.Green;
    Console.Write("[1] Generar nueva licencia");
    Console.ResetColor();
    Console.WriteLine();
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.Write("[2] Validar licencia");
    Console.ResetColor();
    Console.WriteLine();
    Console.Write("[3] Salir");
    Console.WriteLine();
    Console.Write("Seleccione una opción: ");

    var opt = Console.ReadLine()?.Trim();

    switch (opt)
    {
        case "1":
            GenerateAndShowKeys();
            break;
        case "2":
            ValidateKey();
            break;
        case "3":
            return;
        default:
            Console.WriteLine("Opción inválida.");
            break;
    }

    Console.WriteLine();
}

void GenerateAndShowKeys()
{
    Console.Write("¿Cuántas licencias desea generar? (1-10): ");
    var input = Console.ReadLine()?.Trim();
    if (!int.TryParse(input, out int count) || count < 1 || count > 10)
        count = 1;

    Console.WriteLine();
    Console.WriteLine("=== Licencias generadas ===");
    Console.WriteLine();

    for (int i = 0; i < count; i++)
    {
        var key = GenerateKey();
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write($"  {i + 1}. ");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine(key);
        Console.ResetColor();
    }

    Console.WriteLine();
    Console.ForegroundColor = ConsoleColor.DarkGray;
    Console.WriteLine("Copie la licencia y envíela al usuario para activar Secure AI Plus.");
    Console.WriteLine("En Secure AI: Settings -> Secure AI Plus -> Ingrese el código.");
    Console.ResetColor();
}

void ValidateKey()
{
    Console.Write("Ingrese la licencia a validar: ");
    var key = Console.ReadLine()?.Trim();

    if (string.IsNullOrEmpty(key))
    {
        Console.WriteLine("Licencia inválida.");
        return;
    }

    var clean = key.Replace("-", "").Trim().ToUpperInvariant();
    if (clean.Length != 30)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("✗ Licencia INVÁLIDA - Longitud incorrecta.");
        Console.ResetColor();
        return;
    }

    var raw = clean.Substring(0, RawLength);
    var checksum = clean.Substring(RawLength, GroupSize);

    if (raw.Any(c => !ValidChars.Contains(c)) || checksum.Any(c => !ValidChars.Contains(c)))
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("✗ Licencia INVÁLIDA - Caracteres no válidos.");
        Console.ResetColor();
        return;
    }

    using var hmac = new HMACSHA256(SecretKey);
    var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(raw));
    var expectedChars = new char[GroupSize];
    for (int i = 0; i < GroupSize; i++)
        expectedChars[i] = ValidChars[hash[i] % ValidChars.Length];
    var expected = new string(expectedChars);

    if (checksum == expected)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("✓ Licencia VÁLIDA");
        Console.ResetColor();
    }
    else
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("✗ Licencia INVÁLIDA - Checksum incorrecto.");
        Console.ResetColor();
    }
}

string GenerateKey()
{
    var random = RandomNumberGenerator.GetBytes(RawLength);
    var sb = new StringBuilder(RawLength);
    foreach (var b in random)
        sb.Append(ValidChars[b % ValidChars.Length]);

    var raw = sb.ToString();

    using var hmac = new HMACSHA256(SecretKey);
    var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(raw));

    var csChars = new char[GroupSize];
    for (int i = 0; i < GroupSize; i++)
        csChars[i] = ValidChars[hash[i] % ValidChars.Length];
    var checksum = new string(csChars);

    return FormatKey(raw + checksum);
}

string FormatKey(string raw)
{
    var parts = new List<string>();
    for (int i = 0; i < raw.Length; i += GroupSize)
        parts.Add(raw.Substring(i, GroupSize));
    return string.Join("-", parts);
}
