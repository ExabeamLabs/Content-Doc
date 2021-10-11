#### Parser Content
```Java
{
Name = cef-540
  Vendor = Microsoft
  Product = Windows
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
    """\sduid=\([^,]{1,2000},({logon_id}[^\)]{1,2000})""",
    """\scn1=({logon_type}\d{1,100})""",
    """\sdvchost=({host}[^\s]{1,2000})""",
    """ dntdom=({domain}[^\s]{1,2000})""",
    """ src=(?:-|({src_ip}[\w:.]{1,2000}))\s{1,100}\w+="""
  ]
  DupFields = [ "host->dest_host" ]
}
```