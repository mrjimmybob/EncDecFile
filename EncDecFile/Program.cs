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

using System.Threading;
using System.Text.RegularExpressions;
using System.Security.Permissions;


namespace EncDecFile
{
    
    public static class LangHelper
    {
        private static ResourceManager _rm;
        static LangHelper()
        { 
            _rm = new ResourceManager("EncDecFile.Language.strings",
                Assembly.GetExecutingAssembly());
        }

        public static string GetString(string name)
        {
            return _rm.GetString(name);
        }

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
        static int versionRevision = 0;

        enum Operation
        {
            Auto,
            Decrypt,
            Encrypt,
            String,
            Error
        }

        static public string[] GetGroupNames(string domainName, string userName)
        {
            List<string> result = new List<string>();

            using (PrincipalContext principalContext = new PrincipalContext(ContextType.Domain, domainName)) {
                using (PrincipalSearchResult<Principal> src = UserPrincipal.FindByIdentity(principalContext, userName).GetGroups()) {
                    src.ToList().ForEach(sr => result.Add(sr.SamAccountName));
                }
            }
 
            return result.ToArray();
        }

        static private bool GotPermision()
        {
            IntPtr logonToken = WindowsIdentity.GetCurrent().Token;
            using (WindowsIdentity windowsId = new WindowsIdentity(logonToken)) {

                string ssid = windowsId.User.ToString();

                // List<string> result = new List<string>();

                foreach (IdentityReference group in windowsId.Groups) {
                    try {
                        // result.Add(group.Translate(typeof(NTAccount)).ToString());
                        string str = group.Translate(typeof(NTAccount)).ToString();
                        if (str.Contains("gudepssii")) {
                            return true;
                        }
                    }
                    catch {
                        return false;
                    }
                }
                return false;
            }
        }

 
        static void printError(string name, string error, string detail)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write(error + ": ");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write("\'" + name + "\' ");
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("(" + detail + ")");
            Console.ForegroundColor = ConsoleColor.White;
        }

        static void printInfo(string str1, string str2)
        {
			Console.ForegroundColor = ConsoleColor.Green;
            Console.Write(str1);
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(str2);
            Console.ForegroundColor = ConsoleColor.White;
        }
		
        static void printProgress(string status)
        {
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.Write(status);
            Console.ForegroundColor = ConsoleColor.White;

        }

        static void usage()
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

            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"{LangHelper.GetString("usage")}: ");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("    EncDecFile ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("-d ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(LangHelper.GetString("filename"));
            Console.Write($" [");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("-o ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(LangHelper.GetString("outputfile"));
            Console.WriteLine("]");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("    EncDecFile ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("-e ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(LangHelper.GetString("filename"));
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(" [");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("-o ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(LangHelper.GetString("outputfile"));
            Console.WriteLine("]");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("    EncDecFile ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("-a ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(LangHelper.GetString("filename"));
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(" [");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("-o ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(LangHelper.GetString("outputfile"));
            Console.WriteLine("]");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("    EncDecFile ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("-s ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine(LangHelper.GetString("string"));
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"{LangHelper.GetString("options")} :");
            Console.WriteLine($"-d {LangHelper.GetString("filename")}       {LangHelper.GetString("d_opt_desc")}.");
            Console.WriteLine($"-e {LangHelper.GetString("filename")}       {LangHelper.GetString("e_opt_desc")}.");
            Console.WriteLine($"-a {LangHelper.GetString("filename")}       {LangHelper.GetString("a_opt_desc")}.");
            Console.WriteLine($"                  {LangHelper.GetString("a_opt_desc2")}.");
            Console.WriteLine($"-o {LangHelper.GetString("outputfile")} {LangHelper.GetString("o_opt_desc")}.");
            Console.WriteLine($"                  {LangHelper.GetString("o_opt_desc2")}.");
            Console.WriteLine($"-s {LangHelper.GetString("string")}         {LangHelper.GetString("s_opt_desc")}.");
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
        static string createOutputFilename(string inputFilename, string outputFilename)
        {
            if (null == outputFilename)
            {
                string ext = null;

                outputFilename = inputFilename + "_encdec";

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

        /*
         <****add**** name = "GestionReclamosGarantia.Properties.Settings.AS400InformesConnectionString"
              ****connectionString**** = "Data Source=SLPA04;Initial Catalog=AS400Informes;Integrated Security=True"
              providerName = "System.Data.SqlClient"/>

        <add key="ServerName" value="SLPA04"/>
         
         */
        static int processFile(Operation encDec, string inputFilename, string outputFilename)
        {
            string[] lines = File.ReadAllLines(inputFilename);
            string candidateString = null;

            bool foundAdd = false;
            int  foundAddAt = 0;
            bool foundCandidateString = false;
            int  foundCandidateStringAt = 0;
 

            int foundStringAt = 0;
            int numEncrypted = 0;
            int numDecrypted = 0;
            int numTryDecrypted = 0;
            int numOther = 0;

            int errno = 0;

            outputFilename = createOutputFilename(inputFilename, outputFilename);

            printInfo($"{LangHelper.GetString("output_file")}: ", outputFilename);

            using (StreamWriter outputFile = new StreamWriter(outputFilename)) {
                foundAdd = false;
                foundCandidateString = false;


                if (encDec == Operation.Auto)
                {
                    printInfo($"{LangHelper.GetString("action")}: ", LangHelper.GetString("automatic_detection"));
                }
                if (encDec == Operation.Decrypt)
                {
                    printInfo($"{LangHelper.GetString("action")}: ", LangHelper.GetString("decrypting"));
                }
                if (encDec == Operation.Encrypt)
                {
                    printInfo($"{LangHelper.GetString("action")}: ", LangHelper.GetString("encrypting"));
                }

                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.Write($"{LangHelper.GetString("processing")}: "); 
                Console.ForegroundColor = ConsoleColor.White;

                foreach (string line in lines) {
                    /* You need to look for 'add' and after a 
                     * 'connectionString' the next string after is the connection string 
                     *  or look for 'value' after a 'appSetting'
                     */
                    foundAddAt = line.IndexOf("add", System.StringComparison.Ordinal);
                    if (foundAddAt != -1) {
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
                    if (foundCandidateStringAt != -1 && foundCandidateStringAt > foundAddAt && foundAdd == true) {
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
                            while (j < line.Length && !line[j].Equals('"')) {
                                //Console.Write(line[j]);
                                j++;
                            }

                            candidateString = line.Substring(foundStringAt + 1, (j - foundStringAt - 1));

                            Encryptor enc = new Encryptor();
                            string result = candidateString;

                            if (encDec == Operation.Auto)
                            {
                                bool autoDecrypted = false;
                                try
                                {
                                    // Try to decrypt
                                    result = enc.Decrypt(candidateString, true);
                                    ++numDecrypted;
                                    autoDecrypted = true;
                                    printProgress("d");
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
                                        printProgress("e");
                                    }
                                    catch
                                    {
                                        // Ignore and cary on processing file, just puke out input line
                                        result = candidateString;
                                    }
                                }
                            }
                            if (encDec == Operation.Encrypt)
                            {
                                // We want to encrypt
                                try
                                {
                                    result = enc.Encrypt(candidateString, true);
                                    ++numEncrypted;
                                    printProgress("e");
                                }
                                catch 
                                {
                                    // Ignore and cary on processing file, just puke out input line
                                    result = candidateString;
                                    printProgress("=");
                                }
                            }
                            if (encDec == Operation.Decrypt)
                            {
                                // We want to decrypt
                                try { 
                                    result = enc.Decrypt(candidateString, true);
                                    ++numDecrypted;
                                    printProgress("d");
                                }
                                catch 
                                {
                                    // Ignore and cary on processing file, just puke out input line
                                    result = candidateString;
                                    ++numTryDecrypted;
                                    printProgress("=");
                                }
                            }

                            // write line to output file
                            // line1 + connectionString + ending

                            string str1 = line.Substring(0, foundStringAt + 1);
                            string str2 = result;
                            string str3 = line.Substring(foundStringAt + candidateString.Length + 1,
                                (line.Length - (foundStringAt + candidateString.Length + 1)));

                            try {
                                outputFile.Write(str1);
                                outputFile.Write(str2);
                                outputFile.WriteLine(str3);
                            }
                            catch (Exception ex)
                            {
                                errno = -1;
                                printError(outputFilename, LangHelper.GetString("error_processing_file"), ex.Message);  
                            }

                            // Reset values and search for next
                            foundAdd = foundCandidateString = false;
                            foundAddAt = foundCandidateStringAt = foundStringAt = -1;
                            candidateString = null;
                        }
                    }
                    else {
                        // Found nothing, just writ eline
                        try
                        {
                            outputFile.WriteLine(line);
                        }
                        catch (Exception ex)
                        {
                            errno = -1;
                            printError(outputFilename, LangHelper.GetString("error_processing_file"), ex.Message);
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

        static bool isDirectory(string path)
        {
            // get the file attributes for file or directory
            FileAttributes attr = File.GetAttributes(path);

            //detect whether its a directory or file
            if ((attr & FileAttributes.Directory) == FileAttributes.Directory) {
                return true;
            }
            return false;
        }

        static string getInputFilename(string[] args)
        {
            if (args.Length < 2 || args.Length > 4 || args.Length == 3)
            {
                // If not 2 or 4 arguments, get out
                return null;
            }
            // You MUST have 2 or 4 arguments (here at least 2 exist)
            if (args[0].Equals("-d", StringComparison.InvariantCulture) 
                || args[0].Equals("-e", StringComparison.InvariantCulture)
                || args[0].Equals("-a", StringComparison.InvariantCulture))
            {
                // following is the inputFilename
                return args[1];
            }
            if (args.Length == 4)
            {
                // If we have 4 arguments, the input file could be the second argument
                if (args[2].Equals("-d", StringComparison.InvariantCulture) 
                    || args[2].Equals("-e", StringComparison.InvariantCulture)
                    || args[2].Equals("-a", StringComparison.InvariantCulture))
                {
                    // following is the inputFilename
                    return args[3];
                }
            }
            return null;
        }

        static string getOutputFilename(string[] args)
        {
            if (args.Length < 2 || args.Length > 4 || args.Length == 3)
            {
                // If not 2 or 4 arguments, get out
                return null;
            }
            // You MUST have 4 arguments, but -o can be 2nd or 4th
            if (args[0].Equals("-o", StringComparison.InvariantCulture))
            {
                // following is the outputFilename
                return args[1];
            }
            if (args.Length == 4)
            {
                // If we have 4 arguments, the output file could be the second argument
                if (args[2].Equals("-o", StringComparison.InvariantCulture))
                {
                    // following is the outputFilename
                    return args[3];
                }
            }
            // If you did not find the -o return null
            return null;
        }

        static void encryptDecryptString(string argumentString)
        {
            bool stringIsEncrypted = false;
            try
            {
                Encryptor enc = new Encryptor();
                String decryptedString = enc.Decrypt(argumentString, true);
                printInfo($"{LangHelper.GetString("decrypted_string")}: ", decryptedString);
                // Hack, you cannon decrypt a non encrypted string
                stringIsEncrypted = true; // I got here, so it did not fail (string is encrypted)
            }
            catch
            {
                // Ignore
            }
            if (!stringIsEncrypted) { 
                // Do not try to encrypt an already encrypted string
                try
                {
                    Encryptor enc = new Encryptor();
                    String encryptedString = enc.Encrypt(argumentString, true);
                    printInfo($"{LangHelper.GetString("encrypted_string")}: ", encryptedString);
                }
                catch
                {
                    // Ignore
                }
            }
        }

        static Operation getOperationType(string[] args)
        {
            if (args.Length < 2 || args.Length > 4 || args.Length == 3)
            {
                // If not 2 or 4 arguments, get out
                return Operation.Error;
            }
            // You MUST have 2 or 4 arguments
            if (args[0].Equals("-d", StringComparison.InvariantCulture) 
                || args[0].Equals("-e", StringComparison.InvariantCulture)
                || args[0].Equals("-a", StringComparison.InvariantCulture)
                || args[0].Equals("-s", StringComparison.InvariantCulture))
            {
                if (args[0].Equals("-e", StringComparison.InvariantCulture))
                {
                    return (Operation.Encrypt);
                }
                if (args[0].Equals("-d", StringComparison.InvariantCulture))
                {
                    return (Operation.Decrypt);
                }
                if (args[0].Equals("-a", StringComparison.InvariantCulture))
                {
                    return (Operation.Auto);
                }
                if (args[0].Equals("-s", StringComparison.InvariantCulture))
                {
                    return (Operation.String);
                }
            }
            if (args.Length == 4)
            {
                // If we have 4 arguments, the input file could be the second argument
                // But the user can only use -s with 2 args.
                if (args[2].Equals("-d", StringComparison.InvariantCulture) 
                    || args[2].Equals("-e", StringComparison.InvariantCulture)
                    || args[2].Equals("-a", StringComparison.InvariantCulture))
                {
                    if (args[2].Equals("-e", StringComparison.InvariantCulture))
                    {
                        return (Operation.Encrypt);
                    }
                    if (args[2].Equals("-d", StringComparison.InvariantCulture))
                    {
                        return (Operation.Decrypt);
                    }
                    if (args[2].Equals("-a", StringComparison.InvariantCulture))
                    {
                        return (Operation.Auto);
                    }
                }
                return Operation.Error;
            }
            return Operation.Auto;
        }

        static void Main(string[] args)
        {
            var watch = System.Diagnostics.Stopwatch.StartNew();
            int errno = 0;

            Operation encDec = getOperationType(args);
            if (encDec == Operation.Error) {
                usage();
                return;
            }

            if (encDec == Operation.String)
            {
                // We just want to encrypt / decrypt a string.
                encryptDecryptString(args[1]);

                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write(LangHelper.GetString("finished_processing_string"));
            }
            else
            {
                string inputFilename = getInputFilename(args);
                string outputFilename = getOutputFilename(args);

                if (null == inputFilename
                    || (args.Length == 4 && null == outputFilename))
                {
                    // if we have no filename, or with have 4 args and no output filename, get out.
                    usage();
                    return;
                }

                if (!File.Exists(inputFilename))
                {
                    printError(inputFilename, "EncDecFile", LangHelper.GetString("file_does_not_exist"));
                    return;
                }
                if (isDirectory(inputFilename))
                {
                    printError(inputFilename, LangHelper.GetString("parameter_error"), LangHelper.GetString("path_is_a_directory_should_be_a_filename"));
                    return;
                }
                if (!GotPermision())
                {
                    printError(LangHelper.GetString("permision_denied"), "EncDecFile", LangHelper.GetString("need_to_be_group_gudepssii"));
                    return;
                }
                if (null != outputFilename)
                {
                    // If given, check if output file exists
                    if (File.Exists(outputFilename))
                    {
                        printError(outputFilename, "EncDecFile", LangHelper.GetString("output_file_already_exists"));
                        return;
                    }
                }
                printInfo($"{LangHelper.GetString("input_file")}: ", inputFilename);

                try
                {
                    errno = processFile(encDec, inputFilename, outputFilename);
                    // the code that you want to measure comes here
                }
                catch (FileNotFoundException ex)
                {
                    printError(inputFilename, LangHelper.GetString("error_processing_file"), ex.Message);
                }
                catch (UnauthorizedAccessException ex)
                {
                    printError(outputFilename, LangHelper.GetString("error_creating_output_file"), ex.Message);
                }
                catch (Exception ex)
                {
                    printError(inputFilename, LangHelper.GetString("unspecified_error_processing_file"), ex.Message);
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
                Console.Write(Convert.ToString(elapsedMs / 1000) + " s");
            }
            else
            {
                Console.Write(Convert.ToString(elapsedMs) + " ms");
            }
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(".");
            Console.ForegroundColor = ConsoleColor.White;
            
            return;
        }
    }
}
