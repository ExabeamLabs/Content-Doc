#### Parser Content
```Java
{
Name = raw-4663-10
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4663"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = ["An attempt was made to access an object.", "computer_name"]
    Fields = [
      """({event_name}An attempt was made to access an object)""",
      """"(?:winlog\.)?computer_name\\*":\\*"({host}[^\\"]{1,2000})""",
      """@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """({event_code}4663)""",
      """Object(:|=).*?Object Type(:|=)\s{0,100}({file_type}.+?)[\s;]{0,2000}Object Name(:|=)\s{0,100}({file_path}({file_parent}.*?)({file_name}[^\\\/;]{1,2000}?(\.({file_ext}[^\.;\\]{1,2000}?))?))[\s;]{0,2000}Handle ID(:|=)""",
      """Process Name(:|=)\s{0,100}(?:|({process}.+?))[\s;]{0,2000}Access Request Information(:|=)""",
      """Process Name(:|=).*\\({process_name}[^\\;]{1,2000}?)[\s;]{0,2000}Access Request Information(:|=)""",
      """Accesses(:|=)\s{0,100}({accesses}.+?)[\s;]{0,2000}Access Mask(:|=)\s{0,100}({access_mask}\w+)""",
      """"AccessList\\*":\\*"({accesses}[^"]{1,2000}?)\s{0,100}"""",
      """"Account\\*":\\*"(({domain}[^\\\s"]{1,2000})\\+)?({user}[^\\\s"]{1,2000})""",
      """"SubjectUserSid\\*":\\*"({user_sid}[^\s"]{1,2000})""",
      """"SubjectLogonId\\*":\\*"({logon_id}[^\s"]{1,2000})""",
      """"ObjectName\\*":\\*"(-|({file_path}({file_parent}.*?)({file_name}[^\\\/;]{1,2000}?(\.({file_ext}[^\.;]{1,2000}?))?)))\s{0,100}"""",
      """"ObjectType":"(-|({file_type}[^\s"]{1,2000}))""",
      """"ProcessName":"(?: |({process}({directory}(?:[^";]{1,2000})?[\\\/])?({process_name}[^\\\/";]{1,2000}?)))\s{0,100}"""",
    ]
    DupFields = ["host->dest_host","directory->process_directory"]
  }
```