#### Parser Content
```Java
{
Name = n-forwarded-cef-680
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = NitroCefSyslog
    DataType = "windows-680"
    TimeFormat = "epoch"
    Conditions = [ "|McAfee|ESM", "43-21100680"]
    Fields = [ """\|McAfee\|.+?\|43-21100({event_code}\d+)(0|1)\|""",
      """({event_name}Logon attempt)""",
      """\srt=({time}\d+)""",
      """src=({host}[a-fA-F:\d.]+)""",
      """nitroCommandID=({result_code}.+?)\s+\w+=""",
      """sntdom=({domain}[^\s]+)""",
      """suser=({user}.+?)\s+\w+=""",
      """shost=({dest_host}.+?)\s+\w+="""
    ]
  }
```