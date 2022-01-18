#### Parser Content
```Java
{
Name = cef-sysmon-process-created
  Vendor = Microsoft
  Product = Microsoft Sysmon
  Lms = ArcSight
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Microsoft Sysmon|Sysmon NXLog|""", """|SysmonTask-SYSMON_CREATE_PROCESS|Process Create|""" ]
  Fields = [
    """CEF:([^\|]{0,2000}\|){5}({activity}[^\|]{1,2000})""",
    """({host}\S+) CEF:""",
    """\Wdvc=({host}[A-Fa-f:\d]{1,2000})""",
    """\Wdvchost=({host}[\w\-.]{1,2000})""",
    """\Wrt=({time}\d{1,100})""",
    """\WeventId=({event_code}\d{1,100})""",
    """\WcategoryOutcome=\/({outcome}.+?)\s{1,100}(\w+=|$)""",
    """\Wdntdom=(NT AUTHORITY|({domain}\S+))""",
    """\Wduser=(SYSTEM|LOCAL|NETWORK SERVICE|({user}[^\s]{1,2000}))""",
    """\Wsproc=({parent_process}({parent_directory}.*?)({parent_process_name}[^\\]{1,2000}?))\s{1,100}(\w+=|$)""",
    """\Wdproc=(SYSTEM|FINANS|({process}({directory}.*?)({process_name}[^\\]{1,2000}?)))\s{1,100}(\w+=|$)""",
    """\Wcs4=\{({parent_process_guid}[^\}]{1,2000})""",
    """\Wcs6=\{({process_guid}[^\}]{1,2000})""",
    """\Wdpid=({pid}\d{1,100})""",
    """\Wcs1=({command_line}.+?)\s{1,100}(\w+=|$)""",
    """\Wcs2=({parent_command_line}.+?)\s{1,100}(\w+=|$)""",
    """\WfileHash=({md5}\S+)""",
  ]
  DupFields = [ "directory->process_directory" ]


}
```