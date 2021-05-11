#### Parser Content
```Java
{
Name = u-4688
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Sumo
  DataType = "windows-process-created"
  IsHVF = true
  TimeFormat = "yyyyMMddHHmmss"
  Conditions = [ "EventCode = 4688;", """A new process has been created""" ]
  Fields = [ 
    """({event_name}A new process has been created)""",
    """Computer(Name)? = "{1,20}({host}[^"]+)"""",
    """EventCode = ({event_code}\d{1,100})""",
    """TimeGenerated = "({time}[\d]+)\.\d\d\d""",
    """Account Name:\s{1,100}(?:|({user}.+?))\s{1,100}Account Domain:\s{1,100}(?:|({domain}.+?))\s{1,100}Logon ID:""",
    """New Process Name:\s{1,100}(?:|({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/\s]+)))\s{1,100}Token Elevation Type:""",
    """New Process Name:\s{1,100}(?:|({path}.+?))\s{1,100}Token Elevation Type:"""
    """Logon ID:\s{1,100}({logon_id}[^\s]+)\s{1,100}Process""",
    """Security ID:\s{1,100}({user_sid}[^\s]+)\s""",
    """Process Command Line:\s{1,100}(?:|({command_line}.+?))\s{1,100}Token Elevation Type """,
    """Process Command Line:\s{0,100}(|-|(sc|((?:[^"]+)?[\\\/])?sc.exe)\s{0,100}(?:\\*[\w.\-]+)?\s{0,100}create\s{0,100}({service_name}.+?))\s{1,100}binPath= (?:|({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/\s]+)))\s{1,100}Token Elevation Type """,
    """Creator Process ID:\s{1,100}({parent_process_guid}[^\s]+)\s""",
    """New Process ID:\s{1,100}({process_guid}[^\s]+)\s""",
    """({activity_type}Process Creation)"""
  ]
  DupFields = [ "host->dest_host","process_guid->pid","directory->process_directory" ]
}
```