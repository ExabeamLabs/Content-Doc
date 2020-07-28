#### Parser Content
```Java
{
Name = cef-sysmon-process-network
  Vendor = Microsoft
  Product = Sysmon
  Lms = ArcSight
  DataType = "process-network"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Microsoft Sysmon|Sysmon NXLog|""", """|sysmonTask-SYSMON_NETWORK_CONNECT|Network connection detected|""" ]
  Fields = [
    """CEF:([^\|]*\|){5}({activity}[^\|]+)""",
    """({host}\S+) CEF:""",
    """\Wdvc=({host}[A-Fa-f:\d]+)""",
    """\Wdvchost=({host}[\w\-.]+)""",
    """\Wrt=({time}\d+)""",
    """\WeventId=({event_code}\d+)""",
    """\WcategoryOutcome=\/({outcome}.+?)\s+(\w+=|$)""",
    """\Wshost=({src_host}[\w\-.]+)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wspt=({src_port}\d+)""",
    """\Wdhost=({dest_host}[\w\-.]+)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wdpt=({dest_port}\d+)""",
    """\Wcs3=((NT AUTHORITY|({domain}[^\s\\]+))\\+)?(NETWORK SERVICE|LOCAL|SYSTEM|({user}[^\s\\]+))""",
    """\Wdntdom=(NT AUTHORITY|({domain}\S+))""",
    """\Wduser=(SYSTEM|LOCAL|NETWORK SERVICE|({user}[^\s]+))""",
    """\Wdproc=(SYSTEM|FINANS|({process}({directory}.*?)({process_name}[^\\]+?)))\s+(\w+=|$)""",
    """\Wcs6=\{({process_guid}[^\}]+)""",
    """\Wdpid=({pid}\d+)""",
  ]
  DupFields = [ "directory->process_directory" ]
}
```