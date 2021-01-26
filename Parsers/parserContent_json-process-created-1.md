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
      """"EventTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """"Account":"(({domain}[^"]+?)[\\\/]+)?({user}[^"\\\/]+)"""",
      """({event_code}4688)""",
      """"Activity":"({event_name}[^"]+)""",
      """"Hostname":"({host}[^"]+)""",
      """"CommandLine":"\s*({command_line}[^"]+)""",
      """"NewProcessId":"({process_guid}[^"]+)""",
      """"NewProcessName":"({process}({directory}[^"]*?[\\\/]+)?({process_name}[^"\\\/]+))"""",
      """"SubjectLogonId":"({login_id}[^"]+)""",
      """"SubjectUserName":"(-|SYSTEM|({user}[^"]+?))""""
      """"SubjectDomainName":"(-|({domain}[^"]+?))""""
    ]
    DupFields = [ "host->dest_host", "directory->process_directory" ]
  }
```