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
      """exabeam_host=([^=]+?@\s{0,100})?({host}[\w.-]+)""",
      """"forwarder":"({host}[^"]+)""",
      """"TimeGenerated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (am|AM|pm|PM))""",
      """({event_name}A new process has been created)""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """(?i)(((audit|success)( |_)(success|audit))|information)(\s{1,100}|,)({host}[^(\s|,)]+)""",
      """Computer(Name|_name)?\s{0,100}\\*"?(=|:|>)\s{0,100}"{0,20}({host}[\w\.-]+)(\s|,|"|<\/Computer>|$)""",
      """({host}[\w\-.]+)\s{1,100}({time}\d{1,100}\/\d{1,100}\/\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(am|AM|pm|PM))""",
      """({event_code}4688)""",
      """Process Name(:|=)\s{0,100}({process}({directory}(?:[^";]+)?[\\\/])?({process_name}[^\\\/";]+?))[\s;]*Token Elevation Type(:|=)""",
      """Process Name(:|=)\s{0,100}({path}.+?)[\s;]*Token Elevation Type(:|=)""",
      """Account Name(:|=)\s{0,100}(-|SYSTEM|({user}[^\s]+?))[\s;]*Account Domain(:|=)""",
      """Account Domain(:|=)\s{0,100}(-|({domain}[^\s]+?))[\s;]*Logon ID(:|=)""",
      """Logon ID(:|=)\s{0,100}({logon_id}[^\s;]+)""",
      """New Process Name(:|=)\s{0,100}({process}({directory}[^:]+:[^";:\n]+)[\\\/]+?({process_name}[^\s\\:;]+))""",
      """New Process ID(:|=)\s{0,100}({process_guid}[^\s;]+)(\s|;)""",
      """Creator Process ID(:|=)\s{0,100}({parent_process_guid}[^\s;]+)(\s|;)""",
      """Creator Process Name(:|=)\s{0,100}({parent_process}([^:]+:[^";:\n]+)[\\\/]+?({parent_process_name}[^\\\/";]+?))[\s;]*Process""",
      """Creator Process Name(:|=)\s{0,100}(((?:[^";]+)?[\\\/])?({parent_process_name}[^\\\/";]+?))[\s;]*Process""",
      """Process Command Line(:|=)\s{0,2}"?(|({command_line}.+?))(\s{0,100}Token Elevation Type indicates|;|\s{1,100}$)""",
      """Process Command Line(:|=)\s{0,2}"?(|({command_line}\S[^";]*?))(\s{0,100}Token Elevation Type indicates|"\s|;|\s{1,100}$)""",
      """Process Command Line:\s{0,100}"{0,20}(|-|(sc|((?:[^"]+)?[\\\/])?sc.exe)\s{0,100}(?:\\*[\w.\-]+)?\s{0,100}create\s{0,100}({service_name}.+?))\s{1,100}binPath= \s{0,100}(|-|({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/\s]+)))"{0,20}\s{0,100}Token Elevation Type""",
      """TaskCategory=({activity_type}Process Creation)""",
      """"CommandLine":"({command_line}[^"]+?)\s{0,100}"""",
      """"NewProcessName":"({process}({directory}(?:[^";]+)?[\\\/])?({process_name}[^\\\/";]+?))\s{0,100}"""",
      """"ProcessId":"({process_id}[^"]+)""",
      """"SubjectAccount":"(({domain}[^\\\s"]+)\\+)?({user}[^\\\s"]+)""",
      """"SubjectLogonId":"({logon_id}[^"]+)""",
      """"NewProcessId":"({process_guid}[^"]+)""",
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