#### Parser Content
```Java
{
Name = cef-4771
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-4771"
  TimeFormat = "epoch"
  Conditions = [ """|Microsoft|Microsoft Windows|""","""|Microsoft-Windows-Security-Auditing:4771|""" ]
  Fields = [ """exabeam_EventTime=({eventtime}\d{1,100})""",
    """({event_name}Kerberos pre-authentication failed)""",
    """\sexternalId=({event_code}\d{1,100})""",
    """\srt=({time}\d{1,100})""",
    """\sdvc=({host}[a-fA-F:\d.]{1,2000})""",
    """\sdvchost=({host}[^\s]{1,2000})""",
    """\sduser=({user}.+?)\s{1,100}\w+=""",
    """\sdntdom=({user_sid}[^\s]{1,2000})""",
    """\scs4=({result_code}[^\s]{1,2000})""",
    """destinationServiceName =\s{0,100}\w+\/(?=\w)({domain}.+?)\s{1,100}\w+=""",
    """\scs3=(?:::[\w]{1,2000}:|({dest_ip}[a-fA-F:\d.]{1,2000}))"""
  ]
  DupFields = ["host->dest_host"]


}
```