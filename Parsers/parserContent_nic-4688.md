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
      """Information\s+({host}[\w.\-]+)\s+""",
      """(?:Success|Audit)\s+\w+\s+({host}[^\s]+)""",
      """Process Name:\s+({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/"]+?))\s+Token Elevation Type:""",
      """Process Name:\s+({path}.+?)\s+Token Elevation Type:""",
      """Account Name:\s+(?:-|({user}.+?))\s+Account Domain:\s+(?:-|({domain}.+?))\s+Logon ID:\s+({logon_id}[^\s]+)""",
      """New Process ID:\s+({process_guid}[^\s]+)\s""",
      """Creator Process ID:\s+({parent_process_guid}[^\s]+)\s""",
      """Process Command Line:\s+"({command_line}[^"]+)"\s""",
      """Process Command Line:\s+"(|-|(sc|((?:[^"]+)?[\\\/])?sc.exe)\s*(?:\\*[\w.\-]+)?\s*create\s*({service_name}.+?))\s+binPath= ({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/"]+?))"\s""",
      """TaskCategory=({activity_type}Process Creation)"""
    ]
    DupFields = [ "host->dest_host","process_guid->pid","directory->process_directory" ]
}
```