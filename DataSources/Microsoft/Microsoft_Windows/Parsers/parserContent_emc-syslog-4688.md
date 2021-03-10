#### Parser Content
```Java
{
Name = emc-syslog-4688
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "__li_source_path=", "A new process has been created","""eventid="4688"""" ]
  Fields = [
    """({event_name}A new process has been created)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """__li_source_path="({host}[^"]+)"""",
    """({event_code}4688)""",
    """Process Name:\s+({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/"]+?))\s+Token Elevation Type:""",
    """Process Name:\s+({path}.+?)\s+Token Elevation Type:""",
    """Account Name:\s+({user}.+?)\s+Account Domain:\s+({domain}.+?)\s+Logon ID:\s+({logon_id}[^\s]+)""",
    """New Process ID:\s+({process_guid}[^\s]+)\s""",
    """Creator Process ID:\s+({parent_process_guid}[^\s]+)\s""",
    """Process Command Line:\s+"({command_line}[^"]+)"\s""",
    """TaskCategory=({activity_type}Process Creation)"""
    ]
  DupFields = [ "host->dest_ip","process_guid->pid","directory->process_directory" ]
}
```