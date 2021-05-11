#### Parser Content
```Java
{
Name = n-forwarded-cef-4769
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = NitroCefSyslog
    DataType = "windows-4769"
    TimeFormat = "epoch"
    Conditions = ["|McAfee|ESM", "43-26304769"]
    Fields = ["""\|McAfee\|[^|]+?\|[^|]+?\|43-2630({event_code}\d{1,100})(0|1)\|""",
      """({event_name}A Kerberos service ticket was requested)""",
      """\srt=({time}\d{1,100})""",
      """shost=({host}[^\s]+)""",
      """nitroCommandID=({result_code}.+?)\s{1,100}\w+=""",
      """src=({src_ip}[a-fA-F:\d.]+)""",
      """nitroService_Name=({dest_host}\S+\$)\s""",
      """nitroService_Name=({service_name}\S+)""",
      """sntdom=({domain}[^\s]+)""",
      """suser=({user}[^\s]+)"""
    ]
  }
```