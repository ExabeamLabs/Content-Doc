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
    """({time}\d\d\/\d\d\/\d\d\d\d\s+\d\d:\d\d:\d\d\s+(?i)(AM|PM))""",
    """\w+\s+({time}\w+\s+\d+\s+\d+:\d+:\d+\s+\d+)\s""",
    """({event_code}4688)""",
    """ComputerName=({host}[\w-.]+)\s""",
    """(Success Audit|information)\s+({host}[^\s]+)""",
    """Process Name:\s*({process}({directory}(?:[^";]+)?[\\\/])?({process_name}[^\\\/";]+?))[\s;]*Token Elevation Type:""",
    """Account Name:\s*(-|SYSTEM|({user}[^\s]+?))[\s;]*Account Domain:""",
    """Account Domain:\s*(-|({domain}[^\s]+?))[\s;]*Logon ID:""",
    """Logon ID:\s*({logon_id}[^\s;]+)""",
    """New Process Name:\s*({process}({directory}(?:[^";]+)?[\\\/])?({process_name}[^\\\/";]+?))[\s;]*Token Elevation Type:""",
    """New Process ID:\s*({process_guid}[^\s;]+)(\s|;)""",
    """Creator Process ID:\s*({parent_process_guid}[^\s;]+)(\s|;)""",
    """Creator Process Name:\s*({parent_process}((?:[^";]+)?[\\\/])?({parent_process_name}[^\\\/";]+?))[\s;]*Process"""
    """Process Command Line:\s+"?(\s*|({command_line}.+?))"?\s*Token Elevation Type indicates""",
    """Process Command Line:\s*"*(|-|(sc|((?:[^"]+)?[\\\/])?sc.exe)\s*(?:\\*[\w.\-]+)?\s*create\s*({service_name}.+?))\s+binPath= \s*(|-|({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/\s]+)))"*\s*Token Elevation Type""",
    """binPath=\s*({service_command_line}(?:\"(.+)\")|(?:(\S+)))\s*""",
    """Command\s*Line(:|=).*\s+({parameter_sct}\S+\.sct)""",
    """Command\s*Line(:|=).*\s+"({parameter_sct}.+\.sct)"""",
    """Command\s*Line(:|=).*\s+({parameter_hta}\S+\.hta)""",
    """Command\s*Line(:|=).*\s+"({parameter_hta}.+\.hta)"""",
    """Command\s*Line(:|=).*\s+({parameter_xml}\S+\.xml)""",
    """Command\s*Line(:|=).*\s+\s+"({parameter_xml}.+\.xml)"""",
    """Command\s*Line(:|=).*\s+({parameter_csproj}\S+\.csproj)""",
    """Command\s*Line(:|=).*\s+"({parameter_csproj}.+\.csproj)"""",
    """Command\s*Line(:|=).+?\/u\s*["\s]({parameter_exe}.+?\.exe)""",
    """Command\s*Line(:|=).+?\/u\s*["\s]({parameter_dll}.+?\.dll)"""
  ]
  DupFields = [ "host->dest_host","process_guid->pid","directory->process_directory","process->path" ]
}
```