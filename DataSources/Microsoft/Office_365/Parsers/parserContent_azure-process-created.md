#### Parser Content
```Java
{
Name = azure-process-created
  Vendor = Microsoft
  Product = Office 365
  Lms = Direct
  DataType = "process-created"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
  Conditions = [ """ProcessCreationEvents"""", """"ProcessCommandLine":""", """"ActionType":"ProcessCreated"""" ]
  Fields = [
    """"time":\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
    """"AccountName":"({user}[^"]+)""",
    """"AccountDomain":"({domain}[^"]+)""",
    """"ProcessId":({pid}\d+)""",
    """"FileName":"({process_name}[^"]+)""",
    """"ProcessCommandLine":"\s*({command_line}.+?)\s*",""",
    """"FolderPath":"({process}({directory}[^"]*?[\\\/]+)?({process_name}[^"\\\/]+))"""",
    """"MD5":"({md5}[^"]+)""",
    """"ComputerName":"({host}[^"]+)""",
  ]
}
```