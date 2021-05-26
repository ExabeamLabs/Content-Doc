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
  Fields = [ """exabeam_EventTime=({eventtime}\d{1,100})""",
    """({event_name}Account Logon)""",
    """({event_code}672)""",
    """\srt=({time}\d{1,100})""",
    """src=({dest_ip}[a-fA-F:\d.]{1,2000})""",
    """\ssuser=({user}.+?)\s{1,100}\w+=""",
    """\scs4=({result_code}[^\s]{1,2000})""",
    """\sdvchost=({host}[^\s]{1,2000})""",
    """\sdntdom=({domain}[^\s]{1,2000})""", 
  ]
  DupFields = ["host->dest_host"]
}
```