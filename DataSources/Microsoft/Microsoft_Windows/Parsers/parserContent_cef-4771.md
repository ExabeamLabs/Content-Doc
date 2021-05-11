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
    """\sdvc=({host}[a-fA-F:\d.]+)""",
    """\sdvchost=({host}[^\s]+)""",
    """\sduser=({user}.+?)\s{1,100}\w+=""",
    """\sdntdom=({user_sid}[^\s]+)""",
    """\scs4=({result_code}[^\s]+)""",
    """destinationServiceName=\s{0,100}\w+\/(?=\w)({domain}.+?)\s{1,100}\w+=""",
    """\scs3=(?:::[\w]+:|({dest_ip}[a-fA-F:\d.]+))"""
  ]
  DupFields = ["host->dest_host"]
}
```