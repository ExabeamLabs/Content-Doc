#### Parser Content
```Java
{
Name = cef-4740
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = ArcSight
    DataType = "windows-account-lockout"
    TimeFormat = "epoch"
    Conditions = [ """|Microsoft|Microsoft Windows|""","""|Microsoft-Windows-Security-Auditing:4740|""" ]
    Fields = [ """exabeam_EventTime=({eventtime}\d+)""",
      """({event_name}A user account was locked out)""",
      """\sexternalId=({event_code}\d+)""",
      """\srt=({time}\d+)""",
      """\sshost=({src_host}[^\s]+)""",
      """\ssrc=({src_ip}[a-fA-F:\d.]+)""",
      """\ssntdom=({caller_domain}[^\s]+)""",
      """\ssuser=({caller_user}.+?)\s+\w+=""",
      """\sdntdom=({domain}[^\s]+)""",
      """\sduser=({user}.+?)\s+\w+=""",
      """\sduid=({logon_id}[^\s]+)""",
      """\sdvc=({dest_ip}[a-fA-F:\d.]+)""",
      """\sdvchost=({host}[^\s]+)"""
    ]
    DupFields = [ "host->dest_host" ]
  }
```