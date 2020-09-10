#### Parser Content
```Java
{
Name = json-process-created
    Vendor = Microsoft
    Product = Windows
    Lms = Direct
    DataType = "windows-process-created"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ ""","EventID":"4688",""", """A new process has been created""" ]
    Fields = [
      """"TimeGenerated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """"Account":"(({domain}[^"]+?)[\\\/]+)?({user}[^"\\\/]+)"""",
      """({event_code}4688)""",
      """"Activity":"({event_name}[^"]+)""",
      """"Computer":"({host}[^"]+)""",
      """"CommandLine":"({command_line}[^"]+)""",
      """"NewProcessId":"({process_guid}[^"]+)""",
      """"NewProcessName":"({process}({directory}[^"]*?[\\\/]+)?({process_name}[^"\\\/]+))"""",
      """"SubjectLogonId":"({login_id}[^"]+)""",
    ]
    DupFields = [ "host->dest_host", "directory->process_directory" ]
  }
```