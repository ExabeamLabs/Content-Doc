#### Parser Content
```Java
{
Name = raw-4663-9
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4663"
    IsHVF = true
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = ["An attempt was made to access an object.", """"Account":"""]
    Fields = [
      """({event_name}An attempt was made to access an object)""",
      """({host}[\w\-.]{1,2000})\s{1,100}({time}\d{1,100}\/\d{1,100}\/\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(am|AM|pm|PM))""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """(?i)(((audit|success)( |_)(success|audit))|information)[\s,]({host}[\w\-.]{1,2000}).*Subject:""",
      """({event_code}4663)""",
      """"AccessMask":"({access_mask}[^"]{1,2000})""",
      """"AccessList":"({accesses}[^"]{1,2000}?)\s{0,100}"""",
      """"Account":"(({domain}[^\\\s"]{1,2000})\\+)?({user}[^\\\s"]{1,2000})""",
      """"SubjectUserSid":"({user_sid}[^\s"]{1,2000})""",
      """"SubjectLogonId":"({logon_id}[^\s"]{1,2000})""",
      """"ObjectName":"(-|({file_path}({file_parent}.*?)({file_name}[^\\\/;]{1,2000}?(\.({file_ext}[^\.;]{1,2000}?))?)))\s{0,100}"""",
      """"ObjectType":"(-|({file_type}[^\s"]{1,2000}))""",
      """"ProcessName":"(?: |({process}({directory}(?:[^";]{1,2000})?[\\\/])?({process_name}[^\\\/";]{1,2000}?)))\s{0,100}"""",
    ]
    DupFields = ["host->dest_host","directory->process_directory"]
  }
```