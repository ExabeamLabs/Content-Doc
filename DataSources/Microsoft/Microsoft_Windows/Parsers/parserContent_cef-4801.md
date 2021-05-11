#### Parser Content
```Java
{
Name = cef-4801
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-4801"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Microsoft|Microsoft Windows|""","""|Microsoft-Windows-Security-Auditing:4801|""" ]
  Fields = [ 
    """({event_name}The workstation was unlocked)""",
    """\sexternalId=({event_code}\d{1,100})""",
    """\srt=({time}\d{1,100})""",
    """\sdvc=({host}[a-fA-F:\d.]+)""",
    """\sdvchost=({host}[^\s]+)""",
    """\sdst=({dest_ip}[a-fA-F:\d.]+)""",
    """\sdhost=({dest_host}[^\s]+)""",
    """\sduser=({user}.+?)\s{1,100}\w+=""",
    """\sdntdom=({domain}[^\s]+)""",
    """\sduid=({logon_id}[^\s]+)""",
    ]
  }
```