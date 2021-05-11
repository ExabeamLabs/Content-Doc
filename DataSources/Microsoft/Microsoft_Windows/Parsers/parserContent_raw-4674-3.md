#### Parser Content
```Java
{
Name = raw-4674-3
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-privileged-access"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = ["An operation was attempted on a privileged object", "Computer"]
    Fields = [
      """({event_name}An operation was attempted on a privileged object)""",
      """TimeGenerated=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)""", 
      """Type\s{0,100}=\s{0,100}"({outcome}[^";]+)"""",
      """Computer(\w+)?["\s]*(:|=)\s{0,100}"?({host}[^"\s;]+)""",
      """({event_code}4674)""",
      """"Account":"((NT AUTHORITY|({domain}[^\\\s"]+))\\+)?(LOCAL SERVICE|({user}[^\\\s"]+))\s{0,100}"""",
      """"TargetAccount":"(({target_domain}[^\\\s"]+)\\+)?({target_user}[^\\\s"]+)""",
      """"SubjectUserSid":"({user_sid}[^\s"]+)""",
      """"SubjectLogonId":"({logon_id}[^\s"]+)""",
      """"ObjectServer":"(-|({object_server}[^\s"]+))""",
      """"ObjectName":"(-|({object}[^\s"]+))""",
      """"ObjectType":"(-|({object_type}[^\s"]+))""",
      """"ProcessName":"(?: |({process}({directory}(?:[^";]+)?[\\\/])?({process_name}[^\\\/";]+?)))\s{0,100}"""",
    ]
    DupFields = ["host->dest_host","directory->process_directory"]
  }
```