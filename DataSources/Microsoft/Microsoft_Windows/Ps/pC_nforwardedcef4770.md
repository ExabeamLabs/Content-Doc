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
    """\|McAfee\|[^|]{1,2000}?\|[^|]{1,2000}?\|43-2630({event_code}\d{1,100})(0|1)\|""",
    """\srt=({time}\d{1,100})\s{1,100}cnt""",
    """shost=({host}[^\s]{1,2000})""",
    """src=({src_ip}[a-fA-F:\d.]{1,2000})""",
    """sntdom=({domain}[^\s]{1,2000})""",
    """suser=({user}[^\s]{1,2000})""",
    """nitroAppID=({dest_host}[^\s]{1,2000})"""
    """nitroAppID=({service_name}[^\s]{1,2000})"""
  ]


}
```