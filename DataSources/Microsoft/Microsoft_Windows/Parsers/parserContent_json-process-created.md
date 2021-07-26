#### Parser Content
```Java
{
Name = json-process-created
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-process-created"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ ""","EventID":"4688",""", """A new process has been created""" ]
    Fields = [
      """"TimeGenerated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """"Account":"(({domain}[^"]{1,2000}?)[\\\/]{1,2000})?({user}[^"\\\/]{1,2000})"""",
      """({event_code}4688)""",
      """"Activity":"({event_name}[^"]{1,2000})""",
      """"Computer":"({host}[^"]{1,2000})""",
      """"CommandLine":"({command_line}[^"]{1,2000})""",
      """"NewProcessId":"({process_guid}[^"]{1,2000})""",
      """"NewProcessName":"({process}({directory}[^"]{0,2000}?[\\\/]{1,2000})?({process_name}[^"\\\/]{1,2000}))"""",
      """"SubjectLogonId":"({login_id}[^"]{1,2000})""",
    ]
    DupFields = [ "host->dest_host", "directory->process_directory" ]
  }
```