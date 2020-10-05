#### Parser Content
```Java
{
Name = raw-4663
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4663"
    IsHVF = true
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = ["An attempt was made to access an object.", "Account Name:"]
    Fields = [
      """({event_name}An attempt was made to access an object)""",
      """({host}[\w\-.]+)\s+({time}\d+\/\d+\/\d+\s+\d+:\d+:\d+\s+(am|AM|pm|PM))""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """exabeam_host=({host}[\w.\-]+)""",
      """(?i)(((audit|success)( |_)(success|audit))|information)[\s,]({host}[\w\-.]+).*Subject:""",
      """({event_code}4663)""",
      """Subject:.*?Security ID:\s*({user_sid}.+?)[\s;]*Account Name:\s*({user}.+?)[\s;]*Account Domain:\s*(NT AUTHORITY|({domain}.+?))[\s;]*Logon ID:\s*({logon_id}[^\s;]+)[\s;]*Object""",
      """Object:.*?Object Type:\s*({file_type}.+?)[\s;]*Object Name:\s*({file_path}({file_parent}.*?)({file_name}[^\\\/;]+?(\.({file_ext}[^\.;\\]+?))?))[\s;]*Handle ID""",
      """Process Name:\s*(?:|({process}.+?))[\s;]*Access Request Information:""",
      """Process Name:.*\\({process_name}[^\\;]+?)[\s;]*Access Request Information:""",
      """Process Name:\s*(?:|({process}({directory}(\w:)?(?:[^:;]+)?[\\\/])?({process_name}[^\\\/";]+?)))[\s;]*Access Request Information:""",
      """Accesses:\s*({accesses}.+?)[\s;]*Access Mask:\s*({access_mask}\w+)""",
    ]
    DupFields = ["host->dest_host","directory->process_directory"]
  }
```