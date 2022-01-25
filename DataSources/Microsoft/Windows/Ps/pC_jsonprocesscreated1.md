#### Parser Content
```Java
{
Name = json-process-created-1
    Vendor = Microsoft
    Product = Windows
    Lms = Direct
    DataType = "windows-process-created"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ ""","EventID":4688,""", """A new process has been created""" ]
    Fields = [
      """"EventTime":({time}\d{1,100})""",
      """"EventTime":\s{0,100}"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """"Account":"(({domain}[^"]{1,2000}?)[\\\/]{1,2000})?({user}[^"\\\/]{1,2000})"""",
      """({event_code}4688)""",
      """"Activity":"({event_name}[^"]{1,2000})""",
      """"Hostname":"({host}[^"]{1,2000})""",
      """"CommandLine":"\s{0,100}({command_line}[^"]{1,2000})""",
      """"NewProcessId":"({process_guid}[^"]{1,2000})""",
      """"NewProcessName":"({process}({directory}[^"]{0,2000}?[\\\/]{1,2000})?({process_name}[^"\\\/]{1,2000}))"""",
      """"SubjectLogonId":"({logon_id}[^"]{1,2000})""",
      """"SubjectUserName":"(-|SYSTEM|({user}[^"]{1,2000}?))"""",
      """"SubjectDomainName":"(-|({domain}[^"]{1,2000}?))""""
    ]
    DupFields = [ "host->dest_host", "directory->process_directory" ]
  

}
```