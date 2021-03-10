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
    """Computer(Name)? = "+({host}[^"]+)"""",
    """EventCode = ({event_code}\d+)""",
    """TimeGenerated = "({time}[\d]+)\.\d\d\d""",
    """Account Name:\s+(?:|({user}.+?))\s+Account Domain:\s+(?:|({domain}.+?))\s+Logon ID:""",
    """New Process Name:\s+(?:|({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/\s]+)))\s+Token Elevation Type:""",
    """New Process Name:\s+(?:|({path}.+?))\s+Token Elevation Type:"""
    """Logon ID:\s+({logon_id}[^\s]+)\s+Process""",
    """Security ID:\s+({user_sid}[^\s]+)\s""",
    """Process Command Line:\s+(?:|({command_line}.+?))\s+Token Elevation Type """,
    """Creator Process ID:\s+({parent_process_guid}[^\s]+)\s""",
    """New Process ID:\s+({process_guid}[^\s]+)\s""",
    """({activity_type}Process Creation)"""
  ]
  DupFields = [ "host->dest_host","process_guid->pid","directory->process_directory" ]
}
```