#### Parser Content
```Java
{
Name = cef-624
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-account-created"
  TimeFormat = "epoch"
  Conditions = [ """|Microsoft|Microsoft Windows|""","""|Security:624|""" ]
  Fields = [ """exabeam_EventTime=({eventtime}\d+)""",
    """({event_name}User Account Created)""",
    """({event_code}624)""",
    """\srt=({time}\d+)""",
    """\ssntdom=({domain}[^\s]+)""",
    """\ssuser=({user}.+?)\s+\w+=""",
    """\ssuid=\([^,]+,({logon_id}[^\)]+)""",
    """\sdntdom=({account_domain}.+?)\s+\w+=""",
    """\sduser=({account_name}.+?)\s+\w+=""",
    """\sdvchost=({host}[^\s]+)"""
  ]
  DupFields = ["host->dest_host"]
}
```