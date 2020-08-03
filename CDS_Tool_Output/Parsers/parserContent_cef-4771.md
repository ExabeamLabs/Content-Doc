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
  Fields = [ """exabeam_EventTime=({eventtime}\d+)""",
    """({event_name}Kerberos pre-authentication failed)""",
    """\sexternalId=({event_code}\d+)""",
    """\srt=({time}\d+)""",
    """\sdvc=({host}[a-fA-F:\d.]+)""",
    """\sdvchost=({host}[^\s]+)""",
    """\sduser=({user}.+?)\s+\w+=""",
    """\sdntdom=({user_sid}[^\s]+)""",
    """\scs4=({result_code}[^\s]+)""",
    """destinationServiceName=\s*\w+\/(?=\w)({domain}.+?)\s+\w+=""",
    """\scs3=(?:::[\w]+:|({dest_ip}[a-fA-F:\d.]+))"""
  ]
  DupFields = ["host->dest_host"]
}
```