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
      """\|McAfee\|[^|]{1,2000}?\|[^|]{1,2000}?\|43-2630({event_code}\d{1,100})(0|1)\|""",
      """\srt=({time}\d{1,100}?)(\s|0\||$)""",
      """\ssrc=({dest_ip}[A-Fa-f:\d.]{1,2000}?)(\s|0\||$)""",
      """\sshost=({dest_host}[^\s]{1,2000}?)(\s|0\||$)""",
      """\ssntdom=({domain}[^\s]{1,2000}?)(\s|0\||$)""",
      """\ssuser=({user}.+?)(\s{1,100}\w+=|0\|\s{0,100}$)""",
      """\sact=({outcome}.+?)(\s{1,100}\w+=|0\|\s{0,100}$)""",
      """\snitroSource_Logon_ID=({logon_id}.+?)(\s|0\||$)""",
      """\snitroPrivileges=({privileges}.+?)(\s{1,100}\w+=|0\|\s{0,100}$)""",
    ]
    DupFields = ["dest_ip->host", "dest_host->host"]
  }
```