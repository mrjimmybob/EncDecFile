using System;
using System.IO;
using EncryptorLibrary;

using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Linq;

using System.Security.Principal;
using System.Globalization;
using System.Reflection;
using System.Resources;

// using System.Threading;
// using System.Text.RegularExpressions;
// using System.Security.Permissions;
// using static System.Net.WebRequestMethods;
// using File = System.IO.File;


namespace EncDecFile
{

    public static class LangHelper
    {
        private static readonly ResourceManager rm = new ResourceManager("EncDecFile.Language.strings",
                Assembly.GetExecutingAssembly());

        public static string GetString(string name) => rm.GetString(name);

        public static void ChangeLanguage(string language)
        {
            var cultureInfo = new CultureInfo(language);
            CultureInfo.CurrentCulture = cultureInfo;
            CultureInfo.CurrentUICulture = cultureInfo;
        }
    }

    class Program
    {
        static int versionMajor = 3;
        static int versionMinor = 1;
        static int versionRevision = 2;



        static public string[] GetGroupNames(string domainName, string userName)
        {
            List<string> result = new List<string>();

            using (PrincipalContext principalContext = new PrincipalContext(ContextType.Domain, domainName))
            {
                using (PrincipalSearchResult<Principal> src = UserPrincipal.FindByIdentity(principalContext, userName).GetGroups())
                {
                    src.ToList().ForEach(sr => result.Add(sr.SamAccountName));
                }
            }

            return result.ToArray();
        }

        static private bool GotPermision()
        {
            return true;
            IntPtr logonToken = WindowsIdentity.GetCurrent().Token;
            using (WindowsIdentity windowsId = new WindowsIdentity(logonToken))
            {

                string ssid = windowsId.User.ToString();

                foreach (IdentityReference group in windowsId.Groups)
                {
                    try
                    {
                        string str = group.Translate(typeof(NTAccount)).ToString();
                        if (str.Contains("gudepssii"))
                        {
                            return true;
                        }
                    }
                    catch
                    {
                        return false;
                    }
                }
                return false;
            }
        }


        static void PrintError(string name, string error, string detail)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write(error + ": ");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write("\'" + name + "\' ");
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("(" + detail + ")");
            Console.ForegroundColor = ConsoleColor.White;
        }

        static void PrintInfo(string str1, string str2)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write(str1);
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(str2);
            Console.ForegroundColor = ConsoleColor.White;
        }

        static void PrintProgress(string status)
        {
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.Write(status);
            Console.ForegroundColor = ConsoleColor.White;

        }
        static OperationType UserEncriptString(string str)
        {
            ConsoleKeyInfo keyInfo;

            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine($"{LangHelper.GetString("found")}: {str}");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"{LangHelper.GetString("encrypt_decrypt")} ?");
            keyInfo = Console.ReadKey(true); // true to not display the key pressed
            if (keyInfo.KeyChar == 'e' || keyInfo.KeyChar == 'E') return OperationType.Encrypt;
            if (keyInfo.KeyChar == 'd' || keyInfo.KeyChar == 'D') return OperationType.Decrypt;
            return OperationType.Interactive;
        }

        static void PrintOption(string strOption, string strOptionValue, string strOptional = null, string strOptionalValue = null)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("    EncDecFile ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write(strOption + " ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(LangHelper.GetString("filename").Trim());
            if (strOptional != null)
            {
                Console.Write(" [");
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write(strOptional);
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write(LangHelper.GetString("outputfile").Trim());
                Console.WriteLine("]");
            }
        }

        static void Usage()
        {

            // ResourceManager stringManager;
            // stringManager = new ResourceManager("es-ES", Assembly.GetExecutingAssembly());
            CultureInfo ci = CultureInfo.InstalledUICulture;
            LangHelper.ChangeLanguage(ci.TwoLetterISOLanguageName);

            // Console.WriteLine("Default Language Info:");
            // Console.WriteLine("* Name: {0}", ci.Name);
            // Console.WriteLine("* Display Name: {0}", ci.DisplayName);
            // Console.WriteLine("* English Name: {0}", ci.EnglishName);
            // Console.WriteLine("* 2-letter ISO Name: {0}", ci.TwoLetterISOLanguageName);
            // Console.WriteLine("* 3-letter ISO Name: {0}", ci.ThreeLetterISOLanguageName);
            // Console.WriteLine("* 3-letter Win32 API Name: {0}", ci.ThreeLetterWindowsLanguageName);
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"{LangHelper.GetString("progdesc")}");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"{LangHelper.GetString("usage")}: ");
            PrintOption("-d | --decrypt", "filename", "-o | --output ", "outputfile");
            PrintOption("-e | --encrypt", "filename", "-o | --output ", "outputfile");
            PrintOption("-a | --auto", "filename", "-o | --output ", "outputfile");
            PrintOption("-i | --interactive", "filename", "-o | --output ", "outputfile");
            PrintOption("-s | --string", "string");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"{LangHelper.GetString("options")} :");
            Console.WriteLine($"-d | --decrypt {LangHelper.GetString("filename")}\t\t{LangHelper.GetString("d_opt_desc")}.");
            Console.WriteLine($"-e | --encrypt {LangHelper.GetString("filename")}\t\t{LangHelper.GetString("e_opt_desc")}.");
            Console.WriteLine($"-a | --auto {LangHelper.GetString("filename")}\t\t{LangHelper.GetString("a_opt_desc")}.");
            Console.WriteLine($"-i | --interactive {LangHelper.GetString("filename")}\t{LangHelper.GetString("a_opt_desc")}.");
            Console.WriteLine($"\t{LangHelper.GetString("a_opt_desc2")}");
            Console.WriteLine($"-o | --output {LangHelper.GetString("outputfile")} {LangHelper.GetString("o_opt_desc")}.");
            Console.WriteLine($"\t{LangHelper.GetString("o_opt_desc2")}.");
            Console.WriteLine($"-s | --string {LangHelper.GetString("string")}\t\t{LangHelper.GetString("s_opt_desc")}.");
            Console.ForegroundColor = ConsoleColor.DarkYellow;
            Console.Write("Third ");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("3");
            Console.ForegroundColor = ConsoleColor.DarkYellow;
            Console.WriteLine("ye Software Inc. (c) 2021");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("Version: {0}.{1}.{2}. ", versionMajor, versionMinor, versionRevision);
        }

        /*
         * Create automatic outputFilena if none given, if given, return it.
         */
        static string CreateOutputFilename(string inputFilename, string outputFilename)
        {
            if (String.IsNullOrEmpty(outputFilename))
            {

                outputFilename = inputFilename + "_encdec";
                string ext;
                int numExt = 0;
                do
                {
                    ext = numExt.ToString(CultureInfo.InvariantCulture);
                    ++numExt;
                } while (File.Exists(outputFilename + ext));
                outputFilename = outputFilename + ext;
            }

            return outputFilename;
        }

        static int ProcessFile(OperationType op, string inputFilename, string outputFilename)
        {
            string[] lines = File.ReadAllLines(inputFilename);
            string candidateString = null;

            bool foundAdd = false;
            int foundAddAt = 0;
            bool foundCandidateString = false;
            int foundCandidateStringAt = 0;

            OperationType encDec = op;
            int foundStringAt = 0;
            int numEncrypted = 0;
            int numDecrypted = 0;
            int numTryDecrypted = 0;
            int numOther = 0;

            int errno = 0;

            outputFilename = CreateOutputFilename(inputFilename, outputFilename);

            PrintInfo($"{LangHelper.GetString("output_file")}: ", outputFilename);

            using (StreamWriter outputFile = new StreamWriter(outputFilename))
            {
                foundAdd = false;
                foundCandidateString = false;


                if (encDec == OperationType.Auto)
                {
                    PrintInfo($"{LangHelper.GetString("action")}: ", LangHelper.GetString("automatic_detection"));
                }
                if (encDec == OperationType.Decrypt)
                {
                    PrintInfo($"{LangHelper.GetString("action")}: ", LangHelper.GetString("decrypting"));
                }
                if (encDec == OperationType.Encrypt)
                {
                    PrintInfo($"{LangHelper.GetString("action")}: ", LangHelper.GetString("encrypting"));
                }

                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.Write($"{LangHelper.GetString("processing")}: ");
                Console.ForegroundColor = ConsoleColor.White;

                foreach (string line in lines)
                {
                    /* You need to look for 'add' and after a 
                     * 'connectionString' the next string after is the connection string 
                     *  or look for 'value' after a 'appSetting'
                     */
                    foundAddAt = line.IndexOf("add", System.StringComparison.Ordinal);
                    if (foundAddAt != -1)
                    {
                        foundAdd = true;
                    }

                    int foundConnectionStringAt = line.IndexOf("connectionString", StringComparison.Ordinal);
                    int foundValueStringAt = line.IndexOf("value", StringComparison.Ordinal);
                    if (foundValueStringAt >= 0)
                    {
                        foundCandidateStringAt = foundValueStringAt;
                        // If the foundConnectionStringAt is also >= 0, the foundValueStringAt will have no effect (overwriten in next test).
                    }
                    if (foundConnectionStringAt >= 0)
                    {
                        foundCandidateStringAt = foundConnectionStringAt;
                    }
                    if (foundCandidateStringAt != -1 && foundCandidateStringAt > foundAddAt && foundAdd == true)
                    {
                        // the 'connectionString' or 'value' must come after the 'add' key
                        foundCandidateString = true;
                    }
                    if ((foundCandidateString && foundAdd))
                    {
                        // After finding add and the connections string
                        foundStringAt = line.IndexOf("\"", foundCandidateStringAt, StringComparison.Ordinal);
                        if (foundStringAt != -1 && foundStringAt > foundCandidateStringAt)
                        {
                            int j = foundStringAt + 1;
                            while (j < line.Length && !line[j].Equals('"'))
                            {
                                //Console.Write(line[j]);
                                j++;
                            }

                            candidateString = line.Substring(foundStringAt + 1, (j - foundStringAt - 1));

                            Encryptor enc = new Encryptor();
                            string result = candidateString;
                            if (op == OperationType.Interactive)
                            {
                                Console.WriteLine("");
                                encDec = UserEncriptString(candidateString);
                            }
                            else
                            {
                                encDec = op;
                            }

                            if (encDec == OperationType.Auto)
                            {
                                bool autoDecrypted = false;
                                try
                                {
                                    // Try to decrypt
                                    result = enc.Decrypt(candidateString, true);
                                    ++numDecrypted;
                                    autoDecrypted = true;
                                    PrintProgress("d");
                                }
                                catch
                                {
                                    // If decryption fails, it is because it is not encrypted... Encrypt.
                                    result = candidateString;
                                }
                                if (!autoDecrypted)
                                {
                                    // Not been auto decrypted... we should auto encrypt
                                    try
                                    {
                                        result = enc.Encrypt(candidateString, true);
                                        ++numEncrypted;
                                        PrintProgress("e");
                                    }
                                    catch
                                    {
                                        // Ignore and cary on processing file, just puke out input line
                                        result = candidateString;
                                    }
                                }
                            }
                            if (encDec == OperationType.Encrypt)
                            {
                                // We want to encrypt
                                try
                                {
                                    result = enc.Encrypt(candidateString, true);
                                    ++numEncrypted;
                                    PrintProgress("e");
                                }
                                catch
                                {
                                    // Ignore and cary on processing file, just puke out input line
                                    result = candidateString;
                                    PrintProgress("=");
                                }
                            }
                            if (encDec == OperationType.Decrypt)
                            {
                                // We want to decrypt
                                try
                                {
                                    result = enc.Decrypt(candidateString, true);
                                    ++numDecrypted;
                                    PrintProgress("d");
                                }
                                catch
                                {
                                    // Ignore and cary on processing file, just puke out input line
                                    result = candidateString;
                                    ++numTryDecrypted;
                                    PrintProgress("=");
                                }
                            }

                            // write line to output file
                            // line1 + connectionString + ending

                            string str1 = line.Substring(0, foundStringAt + 1);
                            string str2 = result;
                            string str3 = line.Substring(foundStringAt + candidateString.Length + 1,
                                (line.Length - (foundStringAt + candidateString.Length + 1)));

                            try
                            {
                                outputFile.Write(str1);
                                outputFile.Write(str2);
                                outputFile.WriteLine(str3);
                            }
                            catch (Exception ex)
                            {
                                errno = -1;
                                PrintError(outputFilename, LangHelper.GetString("error_processing_file"), ex.Message);
                            }

                            // Reset values and search for next
                            foundAdd = foundCandidateString = false;
                            foundAddAt = foundCandidateStringAt = foundStringAt = -1;
                            candidateString = null;
                        }
                    }
                    else
                    {
                        // Found nothing, just writ eline
                        try
                        {
                            outputFile.WriteLine(line);
                        }
                        catch (Exception ex)
                        {
                            errno = -1;
                            PrintError(outputFilename, LangHelper.GetString("error_processing_file"), ex.Message);
                        }
                        ++numOther;

                        Console.ForegroundColor = ConsoleColor.Magenta;
                        Console.Write(".");
                        Console.ForegroundColor = ConsoleColor.White;
                    }
                }
            }
            Console.WriteLine();
            if (numDecrypted > 0)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.Write($"{LangHelper.GetString("decrypted")} (d): ");
                Console.ForegroundColor = ConsoleColor.Magenta;
                Console.WriteLine(numDecrypted + $" {LangHelper.GetString("string")}" + (numDecrypted == 1 ? "" : "s"));
            }
            if (numTryDecrypted > 0)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.Write($"{LangHelper.GetString("tried_decrypt")} (=): ");
                Console.ForegroundColor = ConsoleColor.Magenta;
                Console.WriteLine(numTryDecrypted + $" {LangHelper.GetString("string")}" + (numTryDecrypted == 1 ? "" : "s"));

            }
            if (numEncrypted > 0)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.Write($"{LangHelper.GetString("encrypted")} (e): ");
                Console.ForegroundColor = ConsoleColor.Magenta;
                Console.WriteLine(numEncrypted + $" {LangHelper.GetString("string")}" + (numEncrypted == 1 ? "" : "s"));
            }
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write($" {LangHelper.GetString("from_a_total_of")}: ");
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine((numEncrypted + numDecrypted + numOther) + " lines");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write($" {LangHelper.GetString("created_output_file")}: ");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(outputFilename);
            Console.ForegroundColor = ConsoleColor.White;
            return errno;
        }

        static bool IsDirectory(string path)
        {
            // get the file attributes for file or directory
            FileAttributes attr = File.GetAttributes(path);

            //detect whether its a directory or file
            if ((attr & FileAttributes.Directory) == FileAttributes.Directory)
            {
                return true;
            }
            return false;
        }


        static (string, OperationType) EncryptDecryptString(string argumentString)
        {
            bool stringIsEncrypted = false;
            try
            {
                Encryptor enc = new Encryptor();
                String decryptedString = enc.Decrypt(argumentString, true);
                // Hack, you cannon decrypt a non encrypted string
                stringIsEncrypted = true; // I got here, so it did not fail (string is encrypted)
                return (decryptedString, OperationType.Decrypt);
            }
            catch
            {
                // Ignore
            }
            if (!stringIsEncrypted)
            {
                // Do not try to encrypt an already encrypted string
                try
                {
                    Encryptor enc = new Encryptor();
                    String encryptedString = enc.Encrypt(argumentString, true);
                    return (encryptedString, OperationType.Encrypt);
                }
                catch
                {
                    // Ignore
                }
            }
            return (String.Empty, OperationType.Error);
        }

        private static Opts GetArgs(string[] args)
        {
            Opts opts = new Opts
            {
                InputFile = String.Empty,
                OutputFile = String.Empty,
                SimpleString = String.Empty,
                Operation = OperationType.Error
            };

            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "-a":
                    case "--auto":
                        if (i + 1 < args.Length)
                        {
                            opts.InputFile = args[++i];
                            opts.Operation = OperationType.Auto;
                        }
                        else
                        {
                            opts.Operation = OperationType.Error;
                            PrintError($"{LangHelper.GetString("error")}", $"{LangHelper.GetString("missing_option")} infile (-a | --auto)", $"{LangHelper.GetString("see_help")} (-h | --help)");
                        }
                        break;

                    case "-d":
                    case "--decrypt":
                        if (i + 1 < args.Length)
                        {
                            opts.InputFile = args[++i];
                            opts.Operation = OperationType.Decrypt;
                        }
                        else
                        {
                            opts.Operation = OperationType.Error;
                            PrintError($"{LangHelper.GetString("error")}", $"{LangHelper.GetString("missing_option")} infile (-d | --decrypt)", $"{LangHelper.GetString("see_help")} (-h | --help)");
                        }
                        break;

                    case "-e":
                    case "--encrypt":
                        if (i + 1 < args.Length)
                        {
                            opts.InputFile = args[++i];
                            opts.Operation = OperationType.Encrypt;
                        }
                        else
                        {
                            opts.Operation = OperationType.Error;
                            PrintError($"{LangHelper.GetString("error")}", $"{LangHelper.GetString("missing_option")} infile (-e | --encrypt)", $"{LangHelper.GetString("see_help")} (-h | --help)");
                        }
                        break;

                    case "-i":
                    case "--interactive":
                        if (i + 1 < args.Length)
                        {
                            opts.InputFile = args[++i];
                            opts.Operation = OperationType.Interactive;
                        }
                        else
                        {
                            opts.Operation = OperationType.Error;
                            PrintError($"{LangHelper.GetString("error")}", $"{LangHelper.GetString("missing_option")} infile (-i | --interactive)", $"{LangHelper.GetString("see_help")} (-h | --help)");
                        }

                        break;

                    case "-o":
                    case "--outfile":
                        if (i + 1 < args.Length)
                        {
                            opts.OutputFile = args[++i];
                        }
                        else
                        {
                            opts.Operation = OperationType.Error;
                            PrintError($"{LangHelper.GetString("error")}", $"{LangHelper.GetString("missing_option")} outfile (-o | --outfile)", $"{LangHelper.GetString("see_help")} (-h | --help)");
                        }
                        break;

                    case "-s":
                    case "--string":
                        if (i + 1 < args.Length)
                        {
                            opts.SimpleString = args[++i];
                            opts.Operation = OperationType.SimpleString;
                        }
                        else
                        {
                            opts.Operation = OperationType.Error;
                            PrintError($"{LangHelper.GetString("error")}", $"{LangHelper.GetString("missing_option")} string (-s | --string)", $"{LangHelper.GetString("see_help")} (-h | --help)");
                        }
                        break;

                    default:
                        opts.Operation = OperationType.Error; // Not needed
                        break;

                }
            }
            return opts;
        }

        static void Main(string[] args)
        {
            var watch = System.Diagnostics.Stopwatch.StartNew();
            int errno = 0;

            Opts opt = GetArgs(args);
            if (opt.Operation == OperationType.Error)
            {
                Usage();
                return;
            }

            if (opt.Operation == OperationType.SimpleString)
            {
                // We just want to encrypt / decrypt a string.
                string str;
                OperationType op = OperationType.Error;
                if (String.IsNullOrEmpty(opt.OutputFile))
                {
                    (str, op) = EncryptDecryptString(opt.SimpleString);
                    switch (op)
                    {
                        case OperationType.Encrypt:
                            PrintInfo($"{LangHelper.GetString("encrypted_string")}: ", str);
                            break;
                        case OperationType.Decrypt:
                            PrintInfo($"{LangHelper.GetString("decrypted_string")}: ", str);
                            break;
                        default:
                            PrintInfo($"{LangHelper.GetString("error")}: ", opt.SimpleString);
                            break;
                    }
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.Write(LangHelper.GetString("finished_processing_string"));
                }
                else
                {
                    string outputFilename = opt.OutputFile;
                    (str, _) = EncryptDecryptString(opt.SimpleString);

                    using (StreamWriter outputFile = new StreamWriter(outputFilename))
                    {
                        try
                        {
                            outputFile.WriteLine(str);
                        }
                        catch (Exception ex)
                        {
                            errno = -1;
                            PrintError(outputFilename, LangHelper.GetString("error_processing_file"), ex.Message);
                        }

                    }
                }
            }
            else
            {
                if (!File.Exists(opt.InputFile))
                {
                    PrintError(opt.InputFile, "EncDecFile", LangHelper.GetString("file_does_not_exist"));
                    return;
                }
                if (IsDirectory(opt.InputFile))
                {
                    PrintError(opt.InputFile, LangHelper.GetString("parameter_error"), LangHelper.GetString("path_is_a_directory_should_be_a_filename"));
                    return;
                }
                if (!GotPermision())
                {
                    PrintError(LangHelper.GetString("permision_denied"), "EncDecFile", LangHelper.GetString("need_to_be_group_gudepssii"));
                    return;
                }
                if (!String.IsNullOrEmpty(opt.OutputFile))
                {
                    // If given, check if output file exists
                    if (File.Exists(opt.OutputFile))
                    {
                        PrintError(opt.OutputFile, "EncDecFile", LangHelper.GetString("output_file_already_exists"));
                        return;
                    }
                }
                PrintInfo($"{LangHelper.GetString("input_file")}: ", opt.InputFile);

                try
                {
                    errno = ProcessFile(opt.Operation, opt.InputFile, opt.OutputFile);
                    // the code that you want to measure comes here
                }
                catch (FileNotFoundException ex)
                {
                    PrintError(opt.InputFile, LangHelper.GetString("error_processing_file"), ex.Message);
                }
                catch (UnauthorizedAccessException ex)
                {
                    PrintError(opt.InputFile, LangHelper.GetString("error_creating_output_file"), ex.Message);
                }
                catch (Exception ex)
                {
                    PrintError(opt.InputFile, LangHelper.GetString("unspecified_error_processing_file"), ex.Message);
                }
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write(LangHelper.GetString("finished_processing_file"));
                if (errno != 0)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.Write($" ({LangHelper.GetString("with_errors")})");
                }


            }
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write($" {LangHelper.GetString("in")} ");
            Console.ForegroundColor = ConsoleColor.Yellow;
            watch.Stop();
            var elapsedMs = watch.ElapsedMilliseconds;
            if (elapsedMs > 1000)
            {
                Console.Write(Convert.ToString(elapsedMs / 1000, CultureInfo.InvariantCulture) + " s");
            }
            else
            {
                Console.Write(Convert.ToString(elapsedMs, CultureInfo.InvariantCulture) + " ms");
            }
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(".");
            Console.ForegroundColor = ConsoleColor.White;

            return;
        }
    }
}
