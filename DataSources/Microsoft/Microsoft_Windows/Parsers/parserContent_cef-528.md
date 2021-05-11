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
    """exabeam_EventTime=({eventtime}\d{1,100})""",
    """({event_code}528)""",
    """\srt=({time}\d{1,100})""",
    """\ssrc=({src_ip}[a-fA-F:\d.]+)""",
    """\ssuser=({user}.+?)\s{1,100}\w+=""",
    """\ssproc=({auth_process}.+?)\s{1,100}\w+=""",
    """\sdntdom=({domain}[^\s]+)""",
    """\sduid=\([^,]+,({logon_id}[^\)]+)""",
    """\scn1=({logon_type}\d{1,100})""",
    """\sdvchost=({host}[^\s]+)""",
    """\sduser=(.*?\\+)?({account}.*?)\s{1,100}\w+=""",
  ]
  DupFields = [ "host->dest_host"]
}
```