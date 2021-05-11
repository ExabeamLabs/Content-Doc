#### Parser Content
```Java
{
Name = azure-process-created
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Direct
  DataType = "process-created"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
  Conditions = [ """ProcessCreationEvents"""", """"ProcessCommandLine":""", """"ActionType":"ProcessCreated"""" ]
  Fields = [
    """"time":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """"AccountName":"({user}[^"]+)""",
    """"AccountDomain":"({domain}[^"]+)""",
    """"ProcessId":({pid}\d{1,100})""",
    """"FileName":"({process_name}[^"]+)""",
    """"ProcessCommandLine":"\s{0,100}({command_line}.+?)\s{0,100}",""",
    """"FolderPath":"({process}({directory}[^"]*?[\\\/]+)?({process_name}[^"\\\/]+))"""",
    """"MD5":"({md5}[^"]+)""",
    """"ComputerName":"({host}[^"]+)""",
  ]
}
```