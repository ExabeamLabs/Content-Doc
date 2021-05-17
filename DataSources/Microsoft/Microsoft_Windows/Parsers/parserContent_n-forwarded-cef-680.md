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
    Fields = [ """\|McAfee\|[^|]{1,2000}?\|[^|]{1,2000}?\|43-21100({event_code}\d{1,100})(0|1)\|""",
      """({event_name}Logon attempt)""",
      """\srt=({time}\d{1,100})""",
      """src=({host}[a-fA-F:\d.]{1,2000})""",
      """nitroCommandID=({result_code}.+?)\s{1,100}\w+=""",
      """sntdom=({domain}[^\s]{1,2000})""",
      """suser=({user}.+?)\s{1,100}\w+=""",
      """shost=({dest_host}.+?)\s{1,100}\w+="""
    ]
  }
```