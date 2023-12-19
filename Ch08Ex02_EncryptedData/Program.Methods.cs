using CryptographyLib;
using static System.IO.Path;
using System.Xml;
using System.Xml.Linq;

partial class Program
{
    public static XDocument ReadXmlFile(string fileName)
    {
        string? fullFilePath = Combine(Environment.CurrentDirectory, fileName);
        WriteLine("Attempting to read {0}", fullFilePath);
        if (!File.Exists(fullFilePath))
        {
            WriteLine($"Cannot read file {fileName}. Please try again.");
            return null;
        }
        return XDocument.Load(fullFilePath);
    }

    public static IEnumerable<string> QueryXmlFile(XDocument xml)
    {
        return from x in xml.Root.Descendants("customer")
               select x.Element("name").Value + "," +
                      x.Element("creditcard").Value + "," +
                      x.Element("password").Value;
    }




}