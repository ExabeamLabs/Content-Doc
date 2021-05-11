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
  Fields = [ """exabeam_EventTime=({eventtime}\d{1,100})""",
    """({event_name}User Account Created)""",
    """({event_code}624)""",
    """\srt=({time}\d{1,100})""",
    """\ssntdom=({domain}[^\s]+)""",
    """\ssuser=({user}.+?)\s{1,100}\w+=""",
    """\ssuid=\([^,]+,({logon_id}[^\)]+)""",
    """\sdntdom=({account_domain}.+?)\s{1,100}\w+=""",
    """\sduser=({account_name}.+?)\s{1,100}\w+=""",
    """\sdvchost=({host}[^\s]+)"""
  ]
  DupFields = ["host->dest_host"]
}
```