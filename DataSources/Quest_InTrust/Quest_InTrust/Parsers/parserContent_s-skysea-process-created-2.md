#### Parser Content
```Java
{
Name = s-skysea-process-created-2
    DataType = "process-created"
    Conditions = [ ",アプリケーション," ]
    Fields = ${SKySeaParserTemplates.s-skysea-dlp.Fields} [
      """^([^\,]{0,2000}\,){4}({session_id}\d)\,""",
      """^([^\,]{0,2000}\,){69}({md5}[^\,]{1,2000})\,""",
      """^([^\,]{0,2000}\,){68}({process}({directory}(?:(\w+:)*([\\\/]{1,2000}[^\\\/"]{1,2000})+)?[\\\/]{1,2000})({process_name}.+?))\,""",
      """^([^\,]{0,2000}\,){8}({activity_type}[^\,]{1,2000})\,"""
    ]
  }
s-skysea-dlp = {
    Vendor = SkySea
    Product = ClientView
    Lms = Splunk
    TimeFormat = "yyyy/MM/dd HH:mm:ss"
    Fields = [
      """({host}[\w\-.]{1,2000}),\d{1,100},""",
      """^([^\,]{0,2000}\,){3}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\,""",
      """^([^\,]{0,2000}\,){5}({user}[^\,]{1,2000})\,""",
      """^([^\,]{0,2000}\,){7}({time}\d{1,100}\/\d{1,100}\/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100})""",
    ]

```