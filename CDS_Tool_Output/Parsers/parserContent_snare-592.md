#### Parser Content
```Java
{
Name = snare-592
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-process-created"
    IsHVF = true
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = ["""A new process has been created:""", """Detailed Tracking""", "\t592\t" ]
    Fields = [ """exabeam_host=({host}[^\s]+)""",
      """({event_name}A new process has been created)""",
      """Security\s*\d+\s+(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d+ \d+:\d+:\d+ \d+)""",
      """({event_code}592)""",
      """(Information|Audit Success|Success Audit)\s+({host}[^\s]+)""",
      """Image File Name:\s+({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/"]+?))\s+Creator Process ID:""",
      """Image File Name:\s+({path}.+?)\s+Creator Process ID:""",
      """User Name:\s+({user}.+?)\s+Domain:\s+({domain}.+?)\s+Logon ID:\s+\([^,]+,({logon_id}[^)]+)""",
      """New Process ID:\s+({process_guid}[^\s]+)\s""",
      """Creator Process ID:\s+({parent_process_guid}[^\s]+)\s"""
    ]
    DupFields = [ "host->dest_host","process_guid->pid","directory->process_directory" ]
  }
```