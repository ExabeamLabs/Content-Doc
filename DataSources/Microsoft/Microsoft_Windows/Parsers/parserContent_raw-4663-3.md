#### Parser Content
```Java
{
Name = raw-4663-3
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4663"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = ["An attempt was made to access an object.", "Microsoft-Windows-Security-Auditing", "Computer"]
    Fields = [
      """({event_name}An attempt was made to access an object)""",
      """TimeGenerated=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)""",
      """Computer=({host}.*?)\s\w+=""",
      """({event_code}4663)""",
      """"AccessList":"({accesses}[^"]+?)\s{0,100}"""",
      """"Account":"(({domain}[^\\\s"]+)\\+)?({user}[^\\\s"]+)""",
      """"SubjectUserSid":"({user_sid}[^\s"]+)""",
      """"SubjectLogonId":"({logon_id}[^\s"]+)""",
      """"ObjectName":"(-|({file_path}({file_parent}.*?)({file_name}[^\\\/;]+?(\.({file_ext}[^\.;]+?))?)))\s{0,100}"""",
      """"ObjectType":"(-|({file_type}[^\s"]+))""",
      """"ProcessName":"(?: |({process}({directory}(?:[^";]+)?[\\\/])?({process_name}[^\\\/";]+?)))\s{0,100}"""",
    ]
    DupFields = ["host->dest_host","directory->process_directory"]
  }
```