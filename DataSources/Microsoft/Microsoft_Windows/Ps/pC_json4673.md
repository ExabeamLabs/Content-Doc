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
      """"Hostname":"({host}[^."]{0,2000})""",
      """({event_code}4673)""",
      """"EventType":"({outcome}[^"]{0,2000})""",
      """"SubjectUserName":"({user}[^"]{0,2000})""",
      """"SubjectDomainName":"({domain}[^"]{0,2000})""",
      """"SubjectLogonId":"({logon_id}[^"]{0,2000})""",
      """"ProcessName":"(?: |({process}({directory}(?:[^"]{1,2000})?[\\\/])?({process_name}[^\\\/"]{1,2000}?)))",""",
      """"ObjectServer":"({object_server}[^"]{0,2000})""",
      """"PrivilegeList":"({privileges}[^"]{0,2000})""",
    ]
    DupFields = ["host->dest_host","directory->process_directory"]
  }
```