#### Parser Content
```Java
{
Name = msnetwork-nac-logon-2
  Vendor = Microsoft
  Product = Microsoft NPS
  Lms = Direct
  DataType = "windows-nac-logon"
  TimeFormat = "MM/dd/yyyy,HH:mm:ss"
  Conditions = [ ""","IAS",""", """,13,"""]
  Fields = [
    """"({host}[^\,]+)","IAS",({time}\d\d\/\d\d\/\d\d\d\d,\d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d,\d*,"({domain}[^\\]+)\\({user}[^"]+)",+?,"({src_ip}[^"]+)",.+?,"({dest_ip}[^"]+)","({src_host}[^"]+)"""",
    """"({dest_host}[^"]+)",\d\d\/\d\d\/\d\d\d\d\s"""
  ]
}
```