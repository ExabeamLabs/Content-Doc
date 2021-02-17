#### Parser Content
```Java
{
Name = cef-4800
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-4800"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Microsoft|Microsoft Windows|""","""|Microsoft-Windows-Security-Auditing:4800|""" ]
  Fields = [ 
    """({event_name}The workstation was locked)""",
    """\sexternalId=({event_code}\d+)""",
    """\srt=({time}\d+)""",
    """\sdvc=({host}[a-fA-F:\d.]+)""",
    """\sdvchost=({host}[^\s]+)""",
    """\sdst=({dest_ip}[a-fA-F:\d.]+)""",
    """\sdhost=({dest_host}[^\s]+)""",
    """\sduser=({user}.+?)\s+\w+=""",
    """\sdntdom=({domain}[^\s]+)""",
    """\sduid=({logon_id}[^\s]+)""",
    ]
  }
```