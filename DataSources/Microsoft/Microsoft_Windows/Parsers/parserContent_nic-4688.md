#### Parser Content
```Java
{
Name = nic-4688
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = RsaSa
    DataType = "windows-process-created"
    IsHVF = true
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = [ "MSWinEventLog", " 4688 Microsoft-Windows-Security-Auditing", "A new process has been created" ]
    Fields = [
      """({event_name}A new process has been created)""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """({time}\w{3}\s\d{2}\s\d{2}:\d{2}:\d{2}\s\d{4})""",
      """({event_code}4688)""",
      """Information\s{1,100}({host}[\w.\-]+)\s{1,100}""",
      """(?:Success|Audit)\s{1,100}\w+\s{1,100}({host}[^\s]+)""",
      """Process Name:\s{1,100}({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/"]+?))\s{1,100}Token Elevation Type:""",
      """Process Name:\s{1,100}({path}.+?)\s{1,100}Token Elevation Type:""",
      """Account Name:\s{1,100}(?:-|({user}.+?))\s{1,100}Account Domain:\s{1,100}(?:-|({domain}.+?))\s{1,100}Logon ID:\s{1,100}({logon_id}[^\s]+)""",
      """New Process ID:\s{1,100}({process_guid}[^\s]+)\s""",
      """Creator Process ID:\s{1,100}({parent_process_guid}[^\s]+)\s""",
      """Process Command Line:\s{1,100}"({command_line}[^"]+)"\s""",
      """Process Command Line:\s{1,100}"(|-|(sc|((?:[^"]+)?[\\\/])?sc.exe)\s{0,100}(?:\\*[\w.\-]+)?\s{0,100}create\s{0,100}({service_name}.+?))\s{1,100}binPath= ({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/"]+?))"\s""",
      """TaskCategory=({activity_type}Process Creation)"""
    ]
    DupFields = [ "host->dest_host","process_guid->pid","directory->process_directory" ]
}
```