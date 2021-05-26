#### Parser Content
```Java
{
Name = cef-sysmon-process-network
  Vendor = Microsoft
  Product = Microsoft Sysmon
  Lms = ArcSight
  DataType = "process-network"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Microsoft Sysmon|Sysmon NXLog|""", """|sysmonTask-SYSMON_NETWORK_CONNECT|Network connection detected|""" ]
  Fields = [
    """CEF:([^\|]{0,2000}\|){5}({activity}[^\|]{1,2000})""",
    """({host}\S+) CEF:""",
    """\Wdvc=({host}[A-Fa-f:\d]{1,2000})""",
    """\Wdvchost=({host}[\w\-.]{1,2000})""",
    """\Wrt=({time}\d{1,100})""",
    """\WeventId=({event_code}\d{1,100})""",
    """\WcategoryOutcome=\/({outcome}.+?)\s{1,100}(\w+=|$)""",
    """\Wshost=({src_host}[\w\-.]{1,2000})""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wspt=({src_port}\d{1,100})""",
    """\Wdhost=({dest_host}[\w\-.]{1,2000})""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wdpt=({dest_port}\d{1,100})""",
    """\Wcs3=((NT AUTHORITY|({domain}[^\s\\]{1,2000}))\\+)?(NETWORK SERVICE|LOCAL|SYSTEM|({user}[^\s\\]{1,2000}))""",
    """\Wdntdom=(NT AUTHORITY|({domain}\S+))""",
    """\Wduser=(SYSTEM|LOCAL|NETWORK SERVICE|({user}[^\s]{1,2000}))""",
    """\Wdproc=(SYSTEM|FINANS|({process}({directory}.*?)({process_name}[^\\]{1,2000}?)))\s{1,100}(\w+=|$)""",
    """\Wcs6=\{({process_guid}[^\}]{1,2000})""",
    """\Wdpid=({pid}\d{1,100})""",
  ]
  DupFields = [ "directory->process_directory" ]
}
```