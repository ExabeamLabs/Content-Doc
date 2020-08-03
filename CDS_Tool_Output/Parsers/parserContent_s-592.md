#### Parser Content
```Java
{
Name = s-592
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-process-created"
    IsHVF = true
    TimeFormat = "MM/dd/yyyy HH:mm:ss a"
    Conditions = [ """EventCode=592""", """EventType=""", """A new process has been created""" ]
    Fields = [
      """exabeam_host=({host}[\w.\-]+)""",
      """({time}\d\d/\d\d/\d\d\d\d \d\d:\d\d:\d\d (am|AM|pm|PM))""",
      """ComputerName=({dest_host}.+?)\s""",
      """({event_code}592)""",
      """User\s*Name:\s*(?:-|({user}.+?))\s+Domain""",
      """Domain:\s*(?:-|({domain}.+?))\s+Logon""",
      """Logon\s*ID:\s*(?:-|({logon_id}.+?))\s*$""",
      """New\s*Process\s*ID:\s*(?:-|({process_guid}\d+))\s""",
      """Creator\s*Process\s*ID:\s*(?:-|({parent_process_guid}\d+))\s""",
      """Image\s*File\s*Name:\s*({process}({directory}(?:[^\s]+)?[\\\/])?({process_name}[^\\\/\s]+))\s""",
      """Image\s*File\s*Name:\s*(?:-|({path}.+?))\s+Creator"""
      """({event_name}A new process has been created)"""
    ]
    DupFields = [ "process_guid->pid","directory->process_directory" ]
  }
```