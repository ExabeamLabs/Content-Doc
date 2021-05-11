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
    """Process Name:\s{1,100}({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/"]+?))\s{1,100}Token Elevation Type:""",
    """Process Name:\s{1,100}({path}.+?)\s{1,100}Token Elevation Type:""",
    """Account Name:\s{1,100}({user}.+?)\s{1,100}Account Domain:\s{1,100}({domain}.+?)\s{1,100}Logon ID:\s{1,100}({logon_id}[^\s]+)""",
    """New Process ID:\s{1,100}({process_guid}[^\s]+)\s""",
    """Creator Process ID:\s{1,100}({parent_process_guid}[^\s]+)\s""",
    """Process Command Line:\s{1,100}"({command_line}[^"]+)"\s""",
    """Process Command Line:\s{1,100}"(|-|(sc|((?:[^"]+)?[\\\/])?sc.exe)\s{0,100}(?:\\*[\w.\-]+)?\s{0,100}create\s{0,100}({service_name}.+?))\s{1,100}binPath= ({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/"]+?))"\s""",
    """TaskCategory=({activity_type}Process Creation)"""
    ]
  DupFields = [ "host->dest_ip","process_guid->pid","directory->process_directory" ]
}
```