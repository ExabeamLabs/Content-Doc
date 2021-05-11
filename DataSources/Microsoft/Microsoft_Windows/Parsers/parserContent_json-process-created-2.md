#### Parser Content
```Java
{
Name = json-process-created-2
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-process-created"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = [ """"event_id""", """4688""", """A new process has been created""" ]
    Fields = [
      """"EventTime"{0,20}:"{0,20}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)\s[^\s]+\sSkyformation""",
      """"@timestamp"{0,20}:"{0,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d{1,100}Z)""",
      """"Account"{0,20}:"{0,20}(({domain}[^"]+?)[\\\/]+)?({user}[^"\\\/]+)"""",
      """({event_code}4688)""",
      """"Activity"{0,20}:"{0,20}({event_name}[^"]+)""",
      """"hostname"{0,20}:"{0,20}({host}[^"]+)""",
      """"CommandLine"{0,20}:"{0,20}({command_line}[^"]+)""",
      """"NewProcessId"{0,20}:"{0,20}({process_guid}[^"]+)""",
      """"NewProcessName"{0,20}:"{0,20}({process}({directory}[^"]*?[\\\/]+)?({process_name}[^"\\\/]+))"""",
      """"SubjectLogonId"{0,20}:"{0,20}({login_id}[^"]+)""",
      """"SubjectUserName"{0,20}:"{0,20}(-|SYSTEM|({user}[^"]+?))""""
      """"SubjectDomainName"{0,20}:"{0,20}(-|({domain}[^"]+?))""""
    ]
    DupFields = [ "host->dest_host", "directory->process_directory" ]
  }
```