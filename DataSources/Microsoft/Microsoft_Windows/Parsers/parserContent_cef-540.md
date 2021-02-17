#### Parser Content
```Java
{
Name = cef-540
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-540"
  TimeFormat = "epoch"
  Conditions = [ """|Microsoft|Microsoft Windows|""", """|Security:540|""" ]
  Fields = [
    """({event_name}Successful Network Logon)""",
    """exabeam_EventTime=({eventtime}\d+)""",
    """({event_code}540)""",
    """\srt=({time}\d+)""",
    """\ssproc=({auth_process}.+?)\s+\w+=""",
    """\sduser=({user}.+?)\s+\w+=""",
    """\sduid=\([^,]+,({logon_id}[^\)]+)""",
    """\scn1=({logon_type}\d+)""",
    """\sdvchost=({host}[^\s]+)""",
    """ dntdom=({domain}[^\s]+)""",
    """ src=(?:-|({src_ip}[\w:.]+))\s+\w+="""
  ]
  DupFields = [ "host->dest_host" ]
}
```