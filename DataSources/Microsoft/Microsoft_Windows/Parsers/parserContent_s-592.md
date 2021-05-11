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
      """User\s{0,100}Name:\s{0,100}(?:-|({user}.+?))\s{1,100}Domain""",
      """Domain:\s{0,100}(?:-|({domain}.+?))\s{1,100}Logon""",
      """Logon\s{0,100}ID:\s{0,100}(?:-|({logon_id}.+?))\s{0,100}$""",
      """New\s{0,100}Process\s{0,100}ID:\s{0,100}(?:-|({process_guid}\d{1,100}))\s""",
      """Creator\s{0,100}Process\s{0,100}ID:\s{0,100}(?:-|({parent_process_guid}\d{1,100}))\s""",
      """Image\s{0,100}File\s{0,100}Name:\s{0,100}({process}({directory}(?:[^\s]+)?[\\\/])?({process_name}[^\\\/\s]+))\s""",
      """Image\s{0,100}File\s{0,100}Name:\s{0,100}(?:-|({path}.+?))\s{1,100}Creator"""
      """({event_name}A new process has been created)"""
    ]
    DupFields = [ "process_guid->pid","directory->process_directory" ]
  }
```