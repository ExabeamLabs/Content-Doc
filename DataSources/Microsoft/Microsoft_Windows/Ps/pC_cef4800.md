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
    """\sexternalId=({event_code}\d{1,100})""",
    """\srt=({time}\d{1,100})""",
    """\sdvc=({host}[a-fA-F:\d.]{1,2000})""",
    """\sdvchost=({host}[^\s]{1,2000})""",
    """\sdst=({dest_ip}[a-fA-F:\d.]{1,2000})""",
    """\sdhost=({dest_host}[^\s]{1,2000})""",
    """\sduser=({user}.+?)\s{1,100}\w+=""",
    """\sdntdom=({domain}[^\s]{1,2000})""",
    """\sduid=({logon_id}[^\s]{1,2000})""",
    ]
  }
```