#### Parser Content
```Java
{
Name = cef-672
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-672"
  TimeFormat = "epoch"
  Conditions = [ """|Microsoft|Microsoft Windows|""","""|Security:672|""" ]
  Fields = [ """exabeam_EventTime=({eventtime}\d+)""",
    """({event_name}Account Logon)""",
    """({event_code}672)""",
    """\srt=({time}\d+)""",
    """src=({dest_ip}[a-fA-F:\d.]+)""",
    """\ssuser=({user}.+?)\s+\w+=""",
    """\scs4=({result_code}[^\s]+)""",
    """\sdvchost=({host}[^\s]+)"""
  ]
}
```