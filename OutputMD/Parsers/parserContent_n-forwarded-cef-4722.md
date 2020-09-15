#### Parser Content
```Java
{
Name = n-forwarded-cef-4722
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = NitroCefSyslog
    DataType = "windows-account-enabled"
    TimeFormat = "epoch"
    Conditions = [ "CEF:", "|McAfee|ESM", "43-26304722"]
    Fields = [ 
      """({event_name}A user account was enabled)""",
      """\|McAfee\|.+?\|43-2630({event_code}\d+)(0|1)\|""",
      """\srt=({time}\d+?)(\s|0\||$)""",
      """\ssrc=({dest_ip}[A-Fa-f:\d.]+?)(\s|0\||$)""",
      """\sshost=({dest_host}[^\s]+?)(\s|0\||$)""",
      """\ssntdom=({domain}[^\s]+?)(\s|0\||$)""",
      """\sdntdom=({target_domain}[^\s]+?)(\s|0\||$)""",
      """\ssuser=({user}.+?)(\s+\w+=|0\||\s*$)""",
      """\sduser=({target_user}.+?)(\s+\w+=|0\||\s*$)""",
      """\snitroSource_Logon_ID=({logon_id}.+?)(\s|0\||$)""",
    ]
    DupFields=[ "dest_ip->host", "dest_host->host" ]
  }
```