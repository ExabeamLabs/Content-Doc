#### Parser Content
```Java
{
Name = raw-4674
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-privileged-access"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = ["An operation was attempted on a privileged object"]
    Fields = [
      """exabeam_host=([^=]+?@\s*)?({host}[\w.-]+)""",
      """({event_name}An operation was attempted on a privileged object)""",
      """({host}[\w\-.]+)\s+({time}\d+\/\d+\/\d+\s+\d+:\d+:\d+\s+(am|AM|pm|PM))""",
      """\scategoryOutcome=(|/({outcome}.+?))(\s+\w+=|\s*$)""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """({outcome}(?i)(((audit|success|failure)( |_)(success|audit|failure))|information))\s*(\s|\t|,|#\d+|<[^>]+>)\s*({host}[^=]+?)\s*(\s|\t|,|#\d+|<[^>]+>)\s*""",
      """Event Type\s*:\s*({outcome}.+?)\.\s+Log Type""",
      """Type\s*=\s*"({outcome}[^";]+)"""",
      """Keywords=({outcome}.+?);?\s*Message=""",
      """\s*Source Address(:|=)\s*(?:-|({src_ip}[^\s]+))\s*Source Port(:|=)""",
      """({event_code}4674)""",
      """Process Name(:|=)\s*(?: |({process}({directory}(?:[^";]+)?[\\\/])?({process_name}[^\\\/";]+?)))[\s;]*Requested""",
      """\s*Account Name(:|=)\s*(?:-|({user}.+?))[\s;]*Account Domain(:|=)\s*({domain}.+?)[\s;]*Logon ID(:|=)\s*({logon_id}.+?)[\s;]*Object(:|=)""",
      """\s*Object Server(:|=)\s*({object_server}.+?)[\s;]*Object Type(:|=)\s*(?:-|({object_type}.+?))[\s;]*Object Name(:|=)\s*(?:-||({object}.+?))[\s;]*Object Handle""",
      """Desired Access(:|=)\s*({accesses}.+?)[\s;]*Privileges(:|=)\s*({privileges}.+?)(\s+\d+|\"|,|;|\s+User:|\s$)""",
      """"Account":"((NT AUTHORITY|({domain}[^\\\s"]+))\\+)?(LOCAL SERVICE|({user}[^\\\s"]+))\s*"""",
      """"TargetAccount":"(({target_domain}[^\\\s"]+)\\+)?({target_user}[^\\\s"]+)""",
      """"SubjectUserSid":"({user_sid}[^\s"]+)""",
      """"SubjectLogonId":"({logon_id}[^\s"]+)""",
      """"ObjectServer":"(-|({object_server}[^\s"]+))""",
      """"ObjectName":"(-||({object}[^\s"]+))""",
      """"ObjectType":"(-|({object_type}[^\s"]+))""",
      """"ProcessName":"(?: |({process}({directory}(?:[^";]+)?[\\\/])?({process_name}[^\\\/";]+?)))\s*"""",
    ]
    DupFields = ["host->dest_host","directory->process_directory"]
  }
```