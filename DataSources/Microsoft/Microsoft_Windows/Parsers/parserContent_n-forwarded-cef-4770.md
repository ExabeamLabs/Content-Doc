#### Parser Content
```Java
{
Name = n-forwarded-cef-4770
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = NitroCefSyslog
  DataType = "windows-4770"
  TimeFormat = "epoch"
  Conditions = [ "|McAfee|ESM", "43-26304770"]
  Fields = [
    """({event_name}A Kerberos service ticket was renewed)""",
    """\|McAfee\|.+?\|43-2630({event_code}\d+)(0|1)\|""",
    """\srt=({time}\d+)\s+cnt""",
    """shost=({host}[^\s]+)""",
    """src=({src_ip}[a-fA-F:\d.]+)""",
    """sntdom=({domain}[^\s]+)""",
    """suser=({user}[^\s]+)""",
    """nitroAppID=({dest_host}[^\s]+)"""
    """nitroAppID=({service_name}[^\s]+)"""
  ]
}
```