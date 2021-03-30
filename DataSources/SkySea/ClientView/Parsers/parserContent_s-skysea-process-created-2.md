#### Parser Content
```Java
{
Name = s-skysea-process-created-2
    DataType = "process-created"
    Conditions = [ ",アプリケーション," ]
    Fields = ${SKySeaParserTemplates.s-skysea-dlp.Fields} [
      """^([^\,]*\,){4}({session_id}\d)\,""",
      """^([^\,]*\,){69}({md5}[^\,]+)\,""",
      """^([^\,]*\,){68}({process}({directory}(?:(\w+:)*([\\\/]+[^\\\/"]+)+)?[\\\/]+)({process_name}.+?))\,""",
      """^([^\,]*\,){8}({activity_type}[^\,]+)\,"""
    ]
  }
s-skysea-dlp = {
    Vendor = SkySea
    Product = ClientView
    Lms = Splunk
    TimeFormat = "yyyy/MM/dd HH:mm:ss"
    Fields = [
      """({host}[\w\-.]+),\d+,""",
      """^([^\,]*\,){3}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\,""",
      """^([^\,]*\,){5}({user}[^\,]+)\,""",
      """^([^\,]*\,){7}({time}\d+\/\d+\/\d+ \d+:\d+:\d+)""",
    ]

```