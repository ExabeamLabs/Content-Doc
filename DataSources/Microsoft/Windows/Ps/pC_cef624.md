#### Parser Content
```Java
{
Name = cef-624
  Vendor = Microsoft
  Product = Windows
  Lms = ArcSight
  DataType = "windows-account-created"
  TimeFormat = "epoch"
  Conditions = [ """|Microsoft|Microsoft Windows|""","""|Security:624|""" ]
  Fields = [ """exabeam_EventTime=({eventtime}\d{1,100})""",
    """({event_name}User Account Created)""",
    """({event_code}624)""",
    """\srt=({time}\d{1,100})""",
    """\ssntdom=({domain}[^\s]{1,2000})""",
    """\ssuser=({user}.+?)\s{1,100}\w+=""",
    """\ssuid=\([^,]{1,2000},({logon_id}[^\)]{1,2000})""",
    """\sdntdom=({account_domain}.+?)\s{1,100}\w+=""",
    """\sduser=({account_name}.+?)\s{1,100}\w+=""",
    """\sdvchost=({host}[^\s]{1,2000})"""
  ]
  DupFields = ["host->dest_host"]
}
```