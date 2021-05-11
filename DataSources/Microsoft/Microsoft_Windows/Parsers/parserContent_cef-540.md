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
    """exabeam_EventTime=({eventtime}\d{1,100})""",
    """({event_code}540)""",
    """\srt=({time}\d{1,100})""",
    """\ssproc=({auth_process}.+?)\s{1,100}\w+=""",
    """\sduser=({user}.+?)\s{1,100}\w+=""",
    """\sduid=\([^,]+,({logon_id}[^\)]+)""",
    """\scn1=({logon_type}\d{1,100})""",
    """\sdvchost=({host}[^\s]+)""",
    """ dntdom=({domain}[^\s]+)""",
    """ src=(?:-|({src_ip}[\w:.]+))\s{1,100}\w+="""
  ]
  DupFields = [ "host->dest_host" ]
}
```