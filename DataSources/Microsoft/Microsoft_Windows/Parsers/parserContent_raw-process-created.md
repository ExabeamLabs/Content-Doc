#### Parser Content
```Java
{
Name = raw-process-created
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-process-created"
    IsHVF = true
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = ["""A new process has been created""" ]
    Fields = [
      """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
      """"forwarder":"({host}[^"]{1,2000})""",
      """"TimeGenerated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (am|AM|pm|PM))""",
      """({event_name}A new process has been created)""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """(?i)(((audit|success)( |_)(success|audit))|information)(\s{1,100}|,)({host}[^(\s|,)]{1,2000})""",
      """Computer(Name|_name)?\s{0,100}\\*"?(=|:|>)\s{0,100}"{0,20}({host}[\w\.-]{1,2000})(\s|,|"|<\/Computer>|$)""",
      """({host}[\w\-.]{1,2000})\s{1,100}({time}\d{1,100}\/\d{1,100}\/\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(am|AM|pm|PM))""",
      """({event_code}4688)""",
      """Process Name(:|=)\s{0,100}({process}({directory}(?:[^";]{1,2000})?[\\\/])?({process_name}[^\\\/";]{1,2000}?))[\s;]{0,2000}Token Elevation Type(:|=)""",
      """Process Name(:|=)\s{0,100}({path}.+?)[\s;]{0,2000}Token Elevation Type(:|=)""",
      """Account Name(:|=)\s{0,100}(-|SYSTEM|({user}[^\s]{1,2000}?))[\s;]{0,2000}Account Domain(:|=)""",
      """Account Domain(:|=)\s{0,100}(-|({domain}[^\s]{1,2000}?))[\s;]{0,2000}Logon ID(:|=)""",
      """Logon ID(:|=)\s{0,100}({logon_id}[^\s;]{1,2000})""",
      """New Process Name(:|=)\s{0,100}({process}({directory}[^:]{1,2000}:[^";:\n]{1,2000})[\\\/]{1,2000}?({process_name}[^\s\\:;]{1,2000}))""",
      """New Process ID(:|=)\s{0,100}({process_guid}[^\s;]{1,2000})(\s|;)""",
      """Creator Process ID(:|=)\s{0,100}({parent_process_guid}[^\s;]{1,2000})(\s|;)""",
      """Creator Process Name(:|=)\s{0,100}({parent_process}([^:]{1,2000}:[^";:\n]{1,2000})[\\\/]{1,2000}?({parent_process_name}[^\\\/";]{1,2000}?))[\s;]{0,2000}Process""",
      """Creator Process Name(:|=)\s{0,100}(((?:[^";]{1,2000})?[\\\/])?({parent_process_name}[^\\\/";]{1,2000}?))[\s;]{0,2000}Process""",
      """Process Command Line(:|=)\s{0,2}"?(|({command_line}.+?))(\s{0,100}Token Elevation Type indicates|;|\s{1,100}$)""",
      """Process Command Line(:|=)\s{0,2}"?(|({command_line}\S[^";]{0,2000}?))(\s{0,100}Token Elevation Type indicates|"\s|;|\s{1,100}$)""",
      """Process Command Line:\s{0,100}"{0,20}(|-|(sc|((?:[^"]{1,2000})?[\\\/])?sc.exe)\s{0,100}(?:\\*[\w.\-]{1,2000})?\s{0,100}create\s{0,100}({service_name}.+?))\s{1,100}binPath= \s{0,100}(|-|({process}({directory}(?:[^"]{1,2000})?[\\\/])?({process_name}[^\\\/\s]{1,2000})))"{0,20}\s{0,100}Token Elevation Type""",
      """TaskCategory=({activity_type}Process Creation)""",
      """"CommandLine":"({command_line}[^"]{1,2000}?)\s{0,100}"""",
      """"NewProcessName":"({process}({directory}(?:[^";]{1,2000})?[\\\/])?({process_name}[^\\\/";]{1,2000}?))\s{0,100}"""",
      """"ProcessId":"({process_id}[^"]{1,2000})""",
      """"SubjectAccount":"(({domain}[^\\\s"]{1,2000})\\+)?({user}[^\\\s"]{1,2000})""",
      """"SubjectLogonId":"({logon_id}[^"]{1,2000})""",
      """"NewProcessId":"({process_guid}[^"]{1,2000})""",
      """Command\s{0,100}Line(:|=)\s{0,100}(?:config)\s{1,100}({service_name}\S+)""",
      """binPath=\s{0,100}({service_command_line}(?:\"(.+)\")|(?:(\S+)))\s{0,100}""",
      """Command\s{0,100}Line(:|=).*\s{1,100}({parameter_sct}\S+\.sct)""",
      """Command\s{0,100}Line(:|=).*\s{1,100}"({parameter_sct}.+\.sct)"""",
      """Command\s{0,100}Line(:|=).*\s{1,100}({parameter_hta}\S+\.hta)""",
      """Command\s{0,100}Line(:|=).*\s{1,100}"({parameter_hta}.+\.hta)"""",
      """Command\s{0,100}Line(:|=).*\s{1,100}({parameter_xml}\S+\.xml)""",
      """Command\s{0,100}Line(:|=).*\s{1,100}\s{1,100}"({parameter_xml}.+\.xml)"""",
      """Command\s{0,100}Line(:|=).*\s{1,100}({parameter_csproj}\S+\.csproj)""",
      """Command\s{0,100}Line(:|=).*\s{1,100}"({parameter_csproj}.+\.csproj)"""",
      """Command\s{0,100}Line(:|=).+?\/u\s{0,100}["\s]({parameter_exe}.+?\.exe)""",
      """Command\s{0,100}Line(:|=).+?\/u\s{0,100}["\s]({parameter_dll}.+?\.dll)"""

    ]
   DupFields = [ "host->dest_host","process_guid->pid","directory->process_directory" ]
  }
```