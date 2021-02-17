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
      """"EventTime"*:"*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)\s[^\s]+\sSkyformation""",
      """"@timestamp"*:"*({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d+Z)""",
      """"Account"*:"*(({domain}[^"]+?)[\\\/]+)?({user}[^"\\\/]+)"""",
      """({event_code}4688)""",
      """"Activity"*:"*({event_name}[^"]+)""",
      """"hostname"*:"*({host}[^"]+)""",
      """"CommandLine"*:"*({command_line}[^"]+)""",
      """"NewProcessId"*:"*({process_guid}[^"]+)""",
      """"NewProcessName"*:"*({process}({directory}[^"]*?[\\\/]+)?({process_name}[^"\\\/]+))"""",
      """"SubjectLogonId"*:"*({login_id}[^"]+)""",
      """"SubjectUserName"*:"*(-|SYSTEM|({user}[^"]+?))""""
      """"SubjectDomainName"*:"*(-|({domain}[^"]+?))""""
    ]
    DupFields = [ "host->dest_host", "directory->process_directory" ]
  }
```