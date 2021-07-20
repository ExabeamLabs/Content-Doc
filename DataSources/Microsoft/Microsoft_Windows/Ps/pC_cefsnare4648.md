#### Parser Content
```Java
{
Name = cef-snare-4648
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = ArcSight
    DataType = "windows-account-switch"
    TimeFormat = "epoch"
    Conditions = ["""|Snare|""", """|Microsoft-Windows-Security-Auditing:4648|"""]
    Fields = [
      """({event_name}A logon was attempted using explicit credentials)""",
      """\sexternalId=({event_code}\d{1,100})""",
      """\srt=({time}\d{1,100})""",
      """\sdvc=({dest_ip}[a-fA-F:\d.]{1,2000})""",
      """\sdvchost=({dest_host}[^\s]{1,2000})""",
      """\sduser=({user}.+?)\s{1,100}\w+=""",
      """\ssuser=({user}.+?)\s{1,100}\w+=""",
      """\sduser=({account}.+?)\s{1,100}\w+=""",
      """\sdntdom=({domain}[^\s]{1,2000})""",
      """\sduid=({logon_id}[^\s]{1,2000})""",
      """dproc=(?: |({process}({directory}(?:[^=]{1,2000})?[\\\/])?({process_name}[^\\\/=]{1,2000})))\s{1,100}\w+=""",
      """\ssrc=({src_ip}[a-fA-F:\d.]{1,2000})"""
    ]
    DupFields = ["dest_ip->host", "dest_host->host","directory->process_directory"]
  }
```