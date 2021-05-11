#### Parser Content
```Java
{
Name = json-4673
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-privileged-access"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [""""EventID":4673""", """"SourceModuleType":"""]
    Fields = [
      """({event_name}A privileged service was called)""",
      """"EventTime":\s{0,100}"({time}\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"""",
      """"Hostname":"({host}[^."]*)""",
      """({event_code}4673)""",
      """"EventType":"({outcome}[^"]*)""",
      """"SubjectUserName":"({user}[^"]*)""",
      """"SubjectDomainName":"({domain}[^"]*)""",
      """"SubjectLogonId":"({logon_id}[^"]*)""",
      """"ProcessName":"(?: |({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/"]+?)))",""",
      """"ObjectServer":"({object_server}[^"]*)""",
      """"PrivilegeList":"({privileges}[^"]*)""",
    ]
    DupFields = ["host->dest_host","directory->process_directory"]
  }
```