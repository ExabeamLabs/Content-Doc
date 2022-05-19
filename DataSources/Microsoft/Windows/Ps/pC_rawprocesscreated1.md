#### Parser Content
```Java
{
Name = raw-process-created-1
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "windows-process-created"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = ["""A new process has been created""", """Account Name:""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """"timestamp":"({time}[^"]{1,2000})""",
    """"host":"({host}[^"]{1,2000})""",
    """({event_name}A new process has been created)""",
    """({time}\d\d\/\d\d\/\d\d\d\d\s{1,100}\d\d:\d\d:\d\d\s{1,100}(?i)(AM|PM))""",
    """\w+\s{1,100}({time}\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}\d{1,100})\s""",
    """({event_code}4688)""",
    """ComputerName =({host}[\w-.]{1,2000})\s""",
    """(Success Audit|information)\s{1,100}({host}[^\s]{1,2000})""",
    """Process Name:\s{0,100}({process}({directory}(?:[^";]{1,2000})?[\\\/])?({process_name}[^\\\/";]{1,2000}?))[\s;]{0,2000}Token Elevation Type:""",
    """Account Name:\s{0,100}(-|SYSTEM|({user}[^\s]{1,2000}?))[\s;]{0,2000}Account Domain:""",
    """Account Domain:\s{0,100}(-|({domain}[^\s]{1,2000}?))[\s;]{0,2000}Logon ID:""",
    """Logon ID:\s{0,100}({logon_id}[^\s;]{1,2000})""",
    """New Process Name:\s{0,100}({process}({directory}(?:[^";]{1,2000})?[\\\/])?({process_name}[^\\\/";]{1,2000}?))[\s;]{0,2000}Token Elevation Type:""",
    """New Process ID:\s{0,100}({process_guid}[^\s;]{1,2000})(\s|;)""",
    """Creator Process ID:\s{0,100}({parent_process_guid}[^\s;]{1,2000})(\s|;)""",
    """Creator Process Name:\s{0,100}({parent_process}((?:[^";]{1,2000})?[\\\/])?({parent_process_name}[^\\\/";]{1,2000}?))[\s;]{0,2000}Process Command Line:""",
    """Process Command Line:\s{1,100}"?(\s{0,100}|({command_line}.+?))"?\s{0,100}Token Elevation Type indicates""",
    """Process Command Line:\s{0,100}"{0,20}(|-|(sc|((?:[^"]{1,2000})?[\\\/])?sc.exe)\s{0,100}(?:\\*[\w.\-]{1,2000})?\s{0,100}create\s{0,100}({service_name}.+?))\s{1,100}binPath= \s{0,100}(|-|({process}({directory}(?:[^"]{1,2000})?[\\\/])?({process_name}[^\\\/\s]{1,2000})))"{0,20}\s{0,100}Token Elevation Type""",
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
  DupFields = [ "host->dest_host","process_guid->pid","directory->process_directory","process->path" ]


}
```