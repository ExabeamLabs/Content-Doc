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
    """CEF:([^\|]*\|){5}({activity}[^\|]+)""",
    """({host}\S+) CEF:""",
    """\Wdvc=({host}[A-Fa-f:\d]+)""",
    """\Wdvchost=({host}[\w\-.]+)""",
    """\Wrt=({time}\d{1,100})""",
    """\WeventId=({event_code}\d{1,100})""",
    """\WcategoryOutcome=\/({outcome}.+?)\s{1,100}(\w+=|$)""",
    """\Wdntdom=(NT AUTHORITY|({domain}\S+))""",
    """\Wduser=(SYSTEM|LOCAL|NETWORK SERVICE|({user}[^\s]+))""",
    """\Wsproc=({parent_process}({parent_directory}.*?)({parent_process_name}[^\\]+?))\s{1,100}(\w+=|$)""",
    """\Wdproc=(SYSTEM|FINANS|({process}({directory}.*?)({process_name}[^\\]+?)))\s{1,100}(\w+=|$)""",
    """\Wcs4=\{({parent_process_guid}[^\}]+)""",
    """\Wcs6=\{({process_guid}[^\}]+)""",
    """\Wdpid=({pid}\d{1,100})""",
    """\Wcs1=({command_line}.+?)\s{1,100}(\w+=|$)""",
    """\Wcs2=({parent_command_line}.+?)\s{1,100}(\w+=|$)""",
    """\WfileHash=({md5}\S+)""",
  ]
  DupFields = [ "directory->process_directory" ]
}
```