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
    """Computer(Name)? = "{1,20}({host}[^"]{1,2000})"""",
    """EventCode = ({event_code}\d{1,100})""",
    """TimeGenerated = "({time}[\d]{1,2000})\.\d\d\d""",
    """Account Name:\s{1,100}(?:|({user}.+?))\s{1,100}Account Domain:\s{1,100}(?:|({domain}.+?))\s{1,100}Logon ID:""",
    """New Process Name:\s{1,100}(?:|({process}({directory}(?:[^"]{1,2000})?[\\\/])?({process_name}[^\\\/\s]{1,2000})))\s{1,100}Token Elevation Type:""",
    """New Process Name:\s{1,100}(?:|({path}.+?))\s{1,100}Token Elevation Type:"""
    """Logon ID:\s{1,100}({logon_id}[^\s]{1,2000})\s{1,100}Process""",
    """Security ID:\s{1,100}({user_sid}[^\s]{1,2000})\s""",
    """Process Command Line:\s{1,100}(?:|({command_line}.+?))\s{1,100}Token Elevation Type """,
    """Process Command Line:\s{0,100}(|-|(sc|((?:[^"]{1,2000})?[\\\/])?sc.exe)\s{0,100}(?:\\*[\w.\-]{1,2000})?\s{0,100}create\s{0,100}({service_name}.+?))\s{1,100}binPath= (?:|({process}({directory}(?:[^"]{1,2000})?[\\\/])?({process_name}[^\\\/\s]{1,2000})))\s{1,100}Token Elevation Type """,
    """Creator Process ID:\s{1,100}({parent_process_guid}[^\s]{1,2000})\s""",
    """New Process ID:\s{1,100}({process_guid}[^\s]{1,2000})\s""",
    """({activity_type}Process Creation)"""
  ]
  DupFields = [ "host->dest_host","process_guid->pid","directory->process_directory" ]
}
```