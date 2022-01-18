#### Parser Content
```Java
{
Name = n-forwarded-cef-4673
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = NitroCefSyslog
  DataType = "windows-privileged-access"
  TimeFormat = "epoch"
  Conditions = [ "|McAfee|ESM", "43-263046730"]
  Fields = [
    """({event_name}A privileged service was called.)""",
    """\|McAfee\|[^|]{1,2000}?\|[^|]{1,2000}?\|43-2630({event_code}\d{1,100})(0|1)\|""",
    """\srt=({time}\d{1,100})\s{1,100}cnt""",
    """shost=({host}[^\s]{1,2000})""",
    """src=({src_ip}[a-fA-F:\d.]{1,2000})""",
    """sntdom=({domain}[^\s]{1,2000})""",
    """suser=({user}[^\s]{1,2000})""",
    """nitroPrivileges=({privileges}.+?)(\s{1,100}\w+=|"{0,20}\s{0,100}$)""",
    """\sact=({outcome}[^\s]{1,2000})""",
    """nitroSource_Logon_ID=({logon_id}.+?)(\s{1,100}\w+=|"{0,20}\s{0,100}$)""",
    """nitroSecurity_ID=({user_sid}.+?)(\s{1,100}\w+=|"{0,20}\s{0,100}$)""",
  ]
  DupFields = ["host->dest_host"]


}
```