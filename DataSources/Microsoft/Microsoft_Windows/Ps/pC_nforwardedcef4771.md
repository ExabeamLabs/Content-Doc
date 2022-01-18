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
    """\|McAfee\|[^|]{1,2000}?\|[^|]{1,2000}?\|43-2630({event_code}\d{1,100})(0|1)\|""",
    """\srt=({time}\d{1,100})""",
    """shost=({host}[^\s]{1,2000})""",
    """src=(::[\w]{1,2000}:)?({dest_ip}[a-fA-F:\d.]{1,2000})""",
    """sntdom=({domain}[^\s]{1,2000})""",
    """suser=({user}.+?)\s{1,100}\w+=""",
    """nitroCommandID=({result_code}.+?)\s{1,100}\w+="""
  ]


}
```