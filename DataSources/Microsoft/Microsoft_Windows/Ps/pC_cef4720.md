#### Parser Content
```Java
{
Name = cef-4720
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-account-created"
  TimeFormat = "epoch"
  Conditions = [ """|Microsoft|Microsoft Windows|""","""|Microsoft-Windows-Security-Auditing:4720""" ]
  Fields = [ """exabeam_EventTime=({eventtime}\d{1,100})""",
    """({event_name}A user account was created)""",
    """({event_code}4720)""",
    """\srt=({time}\d{1,100})""",
    """\ssntdom=({domain}[^\s]{1,2000})""",
    """\ssuser=({user}.+?)\s{1,100}\w+=""",
    """\ssuid=({logon_id}[^\s]{1,2000})""",
    """\sdntdom=({account_domain}[^\s]{1,2000})""",
    """\sduser=({account_name}.+?)\s{1,100}\w+=""",
    """\sdvchost=({host}[^\s]{1,2000})""",
    """ad.New_,Account:Security_,ID=({account_id}[^\s]{1,2000})"""
  ]
   DupFields = ["host->dest_host"]


}
```