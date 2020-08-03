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
    """\|McAfee\|.+?\|43-2630({event_code}\d+)(0|1)\|""",
    """\srt=({time}\d+)\s+cnt""",
    """shost=({host}[^\s]+)""",
    """src=({src_ip}[a-fA-F:\d.]+)""",
    """sntdom=({domain}[^\s]+)""",
    """suser=({user}[^\s]+)""",
    """nitroPrivileges=({privileges}.+?)(\s+\w+=|"*\s*$)""",
    """\sact=({outcome}[^\s]+)""",
    """nitroSource_Logon_ID=({logon_id}.+?)(\s+\w+=|"*\s*$)""",
    """nitroSecurity_ID=({user_sid}.+?)(\s+\w+=|"*\s*$)""",
  ]
  DupFields = ["host->dest_host"]
}
```