#### Parser Content
```Java
{
Name = cef-528
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-528"
  TimeFormat = "epoch"
  Conditions = [ """|Microsoft|Microsoft Windows|""", """|Security:528|""" ]
  Fields = [
    """({event_name}Successful Logon)""",
    """exabeam_EventTime=({eventtime}\d+)""",
    """({event_code}528)""",
    """\srt=({time}\d+)""",
    """\ssrc=({src_ip}[a-fA-F:\d.]+)""",
    """\ssuser=({user}.+?)\s+\w+=""",
    """\ssproc=({auth_process}.+?)\s+\w+=""",
    """\sdntdom=({domain}[^\s]+)""",
    """\sduid=\([^,]+,({logon_id}[^\)]+)""",
    """\scn1=({logon_type}\d+)""",
    """\sdvchost=({host}[^\s]+)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```