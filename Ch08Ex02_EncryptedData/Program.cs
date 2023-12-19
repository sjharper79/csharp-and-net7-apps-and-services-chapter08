using CryptographyLib;
using static System.IO.Path;
using System.Xml;
using System.Xml.Linq;

Write("Sensitive Data Encrption and Decryption");
Write("Please enter the filename: ");
string? fileName = ReadLine();
if (string.IsNullOrEmpty(fileName))
{
    WriteLine("You must enter a filename in the current directory.");
    return;
}

XDocument xml = ReadXmlFile(fileName);
IEnumerable<string> query = QueryXmlFile(xml);

WriteLine();
FileStream? xmlFileStream = null!;
XmlWriter xmlWriter = null!;
string? outputFile = "customers2.xml";
try
{
    string newFile = Combine(Environment.CurrentDirectory, outputFile);

    xmlFileStream = File.OpenWrite(newFile);
    xmlWriter = XmlWriter.Create(xmlFileStream, new XmlWriterSettings { Indent = true, CloseOutput = true, NewLineOnAttributes = true });
    xmlWriter.WriteStartDocument();
    xmlWriter.WriteStartElement("customers");
    foreach (string element in query)
    {
        xmlWriter.WriteStartElement("customer");
        string[] values = element.Split(',');
        string? name = values[0];
        string? creditCard = values[1];
        string? password = values[2];
        string? encryptedCreditCard = Protector.Encrypt(creditCard, password);
        xmlWriter.WriteElementString("name", name);
        xmlWriter.WriteElementString("creditcard", encryptedCreditCard);
        xmlWriter.WriteElementString("password", password);
        xmlWriter.WriteEndElement();
    }

    xmlWriter.Flush();
    xmlWriter.Close();
}
catch (Exception)
{
    WriteLine("Something went wrong!");
}

XDocument xml2 = ReadXmlFile(outputFile);
IEnumerable<string> query2 = QueryXmlFile(xml2);

foreach (string element in query2)
{
    string[] values = element.Split(',');
    string? name = values[0];
    string? creditCard = values[1];
    string? password = values[2];
    string? decryptedCreditCard = Protector.Decrypt(creditCard, password);
    WriteLine($"Name: {name}");
    WriteLine($"Credit Card: {decryptedCreditCard}");
}