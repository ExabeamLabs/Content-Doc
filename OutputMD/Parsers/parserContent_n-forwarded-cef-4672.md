#### Parser Content
```Java
{
Name = n-forwarded-cef-4672
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = NitroCefSyslog
    DataType = "windows-privileged-access"
    TimeFormat = "epoch"
    Conditions = ["CEF:", "|McAfee|ESM", "43-26304672"]
    Fields = [
      """({event_name}Special privileges assigned to new logon)""",
      """\|McAfee\|.+?\|43-2630({event_code}\d+)(0|1)\|""",
      """\srt=({time}\d+?)(\s|0\||$)""",
      """\ssrc=({dest_ip}[A-Fa-f:\d.]+?)(\s|0\||$)""",
      """\sshost=({dest_host}[^\s]+?)(\s|0\||$)""",
      """\ssntdom=({domain}[^\s]+?)(\s|0\||$)""",
      """\ssuser=({user}.+?)(\s+\w+=|0\|\s*$)""",
      """\sact=({outcome}.+?)(\s+\w+=|0\|\s*$)""",
      """\snitroSource_Logon_ID=({logon_id}.+?)(\s|0\||$)""",
      """\snitroPrivileges=({privileges}.+?)(\s+\w+=|0\|\s*$)""",
    ]
    DupFields = ["dest_ip->host", "dest_host->host"]
  }
```