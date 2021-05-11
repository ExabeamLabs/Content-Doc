#### Parser Content
```Java
{
Name = raw-4674-2
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-privileged-access"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = ["An operation was attempted on a privileged object", "/Microsoft-Windows-Security-Auditing"]
    Fields = [
      """({event_name}An operation was attempted on a privileged object)""",
      """\scategoryOutcome=(|/({outcome}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """({host}[^\s\/]+)\/Microsoft-Windows-Security-Auditing \(4674\)""",
      """Event Type\s{0,100}:\s{0,100}({outcome}.+?)\.\s{1,100}Log Type""",
      """Type\s{0,100}=\s{0,100}"({outcome}[^";]+)"""",
      """Keywords=({outcome}.+?);?\s{0,100}Message=""",
      """\s{0,100}Source Address(:|=)\s{0,100}(?:-|({src_ip}[^\s]+))\s{0,100}Source Port(:|=)""",
      """({event_code}4674)""",
      """Process Name(:|=)\s{0,100}(?: |({process}({directory}(?:[^";]+)?[\\\/])?({process_name}[^\\\/";]+?)))[\s;]*Requested""",
      """\s{0,100}Account Name(:|=)\s{0,100}(?:-|({user}.+?))[\s;]*Account Domain(:|=)\s{0,100}({domain}.+?)[\s;]*Logon ID(:|=)\s{0,100}({logon_id}.+?)[\s;]*Object(:|=)""",
      """\s{0,100}Object Server(:|=)\s{0,100}({object_server}.+?)[\s;]*Object Type(:|=)\s{0,100}(?:-|({object_type}.+?))[\s;]*Object Name(:|=)\s{0,100}(?:|-|({object}.+?))[\s;]*Object Handle""",
      """Desired Access(:|=)\s{0,100}({accesses}.+?)[\s;]*Privileges(:|=)\s{0,100}({privileges}.+?)(\s{1,100}\d{1,100}|\"|,|;|\s{1,100}User:|\s$)""",
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