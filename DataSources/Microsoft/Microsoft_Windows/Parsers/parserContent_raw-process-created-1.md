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
    """({time}\w+\s+\d+\s+\d+:\d+:\d+\s+\d+)\s+({event_code}4688)""",
    """(Success Audit|information)\s+({host}[^\s]+)""",
    """Process Name:\s*({process}({directory}(?:[^";]+)?[\\\/])?({process_name}[^\\\/";]+?))[\s;]*Token Elevation Type:""",
    """Account Name:\s*(-|SYSTEM|({user}[^\s]+?))[\s;]*Account Domain:""",
    """Account Domain:\s*(-|({domain}[^\s]+?))[\s;]*Logon ID:""",
    """Logon ID:\s*({logon_id}[^\s;]+)""",
    """New Process Name:\s*({process}({directory}(?:[^";]+)?[\\\/])?({process_name}[^\\\/";]+?))[\s;]*Token Elevation Type:""",
    """New Process ID:\s*({process_guid}[^\s;]+)(\s|;)""",
    """Creator Process ID:\s*({parent_process_guid}[^\s;]+)(\s|;)""",
    """Creator Process Name:\s*({parent_process}((?:[^";]+)?[\\\/])?({parent_process_name}[^\\\/";]+?))[\s;]*Process"""
    """Process Command Line:\s+"?({command_line}.+?)"?\s*Token Elevation Type indicates""",
    """Process Command Line:\s*"*(|-|(sc|((?:[^"]+)?[\\\/])?sc.exe)\s*(?:\\*[\w.\-]+)?\s*create\s*({service_name}.+?))\s+binPath= \s*(|-|({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/\s]+)))"*\s*Token Elevation Type""",
  ]
  DupFields = [ "host->dest_host","process_guid->pid","directory->process_directory","process->path" ]
}
```