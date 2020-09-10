#### Parser Content
```Java
{
Name = n-forwarded-cef-4771
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = NitroCefSyslog
  DataType = "windows-4771"
  TimeFormat = "epoch"
  Conditions = [ "|McAfee|ESM", "43-26304771"]
  Fields = [
    """({event_name}Kerberos pre-authentication failed)""",
    """\|McAfee\|.+?\|43-2630({event_code}\d+)(0|1)\|""",
    """\srt=({time}\d+)""",
    """shost=({host}[^\s]+)""",
    """src=(::[\w]+:)?({dest_ip}[a-fA-F:\d.]+)""",
    """sntdom=({domain}[^\s]+)""",
    """suser=({user}.+?)\s+\w+=""",
    """nitroCommandID=({result_code}.+?)\s+\w+="""
  ]
}
```