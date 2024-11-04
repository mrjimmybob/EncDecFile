
namespace EncDecFile
{
  public enum OperationType
  {
    Auto,
    Decrypt,
    Encrypt,
    SimpleString,
    Interactive,
    Error
  }

  internal class Opts
  {
    private OperationType operation;
    private string inputFile;
    private string outputFile;
    private string simpleString;

    public OperationType Operation
    {
      get { return operation; }
      set { operation = value; }
    }

    public string InputFile
    {
      get { return inputFile; }
      set { inputFile = value; }
    }

    public string OutputFile
    {
      get { return outputFile; }
      set { outputFile = value; }
    }

    public string SimpleString
    {
      get { return simpleString; }
      set { simpleString = value; }
    }

  }
}
