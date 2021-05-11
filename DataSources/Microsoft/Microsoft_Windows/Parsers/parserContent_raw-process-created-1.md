#### Parser Content
```Java
{
Name = raw-process-created-1
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-process-created"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = ["""A new process has been created""", """Account Name:""" ]
  Fields = [
    """({event_name}A new process has been created)""",
    """({time}\d\d\/\d\d\/\d\d\d\d\s{1,100}\d\d:\d\d:\d\d\s{1,100}(?i)(AM|PM))""",
    """\w+\s{1,100}({time}\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}\d{1,100})\s""",
    """({event_code}4688)""",
    """ComputerName=({host}[\w-.]+)\s""",
    """(Success Audit|information)\s{1,100}({host}[^\s]+)""",
    """Process Name:\s{0,100}({process}({directory}(?:[^";]+)?[\\\/])?({process_name}[^\\\/";]+?))[\s;]*Token Elevation Type:""",
    """Account Name:\s{0,100}(-|SYSTEM|({user}[^\s]+?))[\s;]*Account Domain:""",
    """Account Domain:\s{0,100}(-|({domain}[^\s]+?))[\s;]*Logon ID:""",
    """Logon ID:\s{0,100}({logon_id}[^\s;]+)""",
    """New Process Name:\s{0,100}({process}({directory}(?:[^";]+)?[\\\/])?({process_name}[^\\\/";]+?))[\s;]*Token Elevation Type:""",
    """New Process ID:\s{0,100}({process_guid}[^\s;]+)(\s|;)""",
    """Creator Process ID:\s{0,100}({parent_process_guid}[^\s;]+)(\s|;)""",
    """Creator Process Name:\s{0,100}({parent_process}((?:[^";]+)?[\\\/])?({parent_process_name}[^\\\/";]+?))[\s;]*Process"""
    """Process Command Line:\s{1,100}"?(\s{0,100}|({command_line}.+?))"?\s{0,100}Token Elevation Type indicates""",
    """Process Command Line:\s{0,100}"{0,20}(|-|(sc|((?:[^"]+)?[\\\/])?sc.exe)\s{0,100}(?:\\*[\w.\-]+)?\s{0,100}create\s{0,100}({service_name}.+?))\s{1,100}binPath= \s{0,100}(|-|({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/\s]+)))"{0,20}\s{0,100}Token Elevation Type""",
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