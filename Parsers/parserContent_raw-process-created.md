#### Parser Content
```Java
{
Name = raw-process-created
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-process-created"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = ["""A new process has been created""" ]
    Fields = [
      """exabeam_host=([^=]+?@\s*)?({host}[\w.-]+)""",
      """"TimeGenerated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (am|AM|pm|PM))""",
      """({event_name}A new process has been created)""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """(?i)(((audit|success)( |_)(success|audit))|information)(\s+|,)({host}[^(\s|,)]+)""",
      """Computer(Name|_name)?\s*\\*"?(=|:|>)\s*"*({host}[\w\.-]+)(\s|,|"|<\/Computer>|$)""",
      """({host}[\w\-.]+)\s+({time}\d+\/\d+\/\d+\s+\d+:\d+:\d+\s+(am|AM|pm|PM))""",
      """({event_code}4688)""",
      """Process Name(:|=)\s*({process}({directory}(?:[^";]+)?[\\\/])?({process_name}[^\\\/";]+?))[\s;]*Token Elevation Type(:|=)""",
      """Process Name(:|=)\s*({path}.+?)[\s;]*Token Elevation Type(:|=)""",
      """Account Name(:|=)\s*(-|SYSTEM|({user}[^\s]+?))[\s;]*Account Domain(:|=)""",
      """Account Domain(:|=)\s*(-|({domain}[^\s]+?))[\s;]*Logon ID(:|=)""",
      """Logon ID(:|=)\s*({logon_id}[^\s;]+)""",
      """New Process Name(:|=)\s*({process}({directory}(?:[^";]+)?[\\\/])?({process_name}[^\\\/";]+?))[\s;]*Token Elevation Type(:|=)""",
      """New Process ID(:|=)\s*({process_guid}[^\s;]+)(\s|;)""",
      """Creator Process ID(:|=)\s*({parent_process_guid}[^\s;]+)(\s|;)""",
      """Creator Process Name(:|=)\s*(((?:[^";]+)?[\\\/])?({parent_process_name}[^\\\/";]+?))[\s;]*Process"""
      """Process Command Line(:|=)\s{0,2}"?(|({command_line}\S[^";]*?))(\s*Token Elevation Type indicates|"\s|;|\s+$)""",
      """Process Command Line:\s*"*(|-|(sc|((?:[^"]+)?[\\\/])?sc.exe)\s*(?:\\*[\w.\-]+)?\s*create\s*({service_name}.+?))\s+binPath= \s*(|-|({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/\s]+)))"*\s*Token Elevation Type""",
      """TaskCategory=({activity_type}Process Creation)""",
      """"CommandLine":"({command_line}[^"]+?)\s*"""",
      """"NewProcessName":"({process}({directory}(?:[^";]+)?[\\\/])?({process_name}[^\\\/";]+?))\s*"""",
      """"ProcessId":"({process_id}[^"]+)""",
      """"SubjectAccount":"(({domain}[^\\\s"]+)\\+)?({user}[^\\\s"]+)""",
      """"SubjectLogonId":"({logon_id}[^"]+)""",
      """"NewProcessId":"({process_guid}[^"]+)""",

    ]
   DupFields = [ "host->dest_host","process_guid->pid","directory->process_directory" ]
  }
```