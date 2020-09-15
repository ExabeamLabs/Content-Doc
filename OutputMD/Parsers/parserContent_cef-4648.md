#### Parser Content
```Java
{
Name = cef-4648
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = ArcSight
    DataType = "windows-account-switch"
    TimeFormat = "epoch"
    Conditions = ["""|Microsoft|Microsoft Windows|""", """|Microsoft-Windows-Security-Auditing:4648|"""]
    Fields = [
      """({event_name}A logon was attempted using explicit credentials)""",
      """\sexternalId=({event_code}\d+)""",
      """\srt=({time}\d+)""",
      """\sdvc=({dest_ip}[a-fA-F:\d.]+)""",
      """\sdvchost=({dest_host}[^\s]+)""",
      """\sduser=({user}.+?)\s+\w+=""",
      """\ssuser=({user}.+?)\s+\w+=""",
      """\sduser=({account}.+?)\s+\w+=""",
      """\sdntdom=({domain}[^\s]+)""",
      """\sduid=({logon_id}[^\s]+)""",
      """dproc=(?: |({process}({directory}(?:[^=]+)?[\\\/])?({process_name}[^\\\/=]+)))\s+\w+=""",
      """\ssrc=({src_ip}[a-fA-F:\d.]+)"""
    ]
    DupFields = ["dest_ip->host", "dest_host->host","directory->process_directory"]
  }
```