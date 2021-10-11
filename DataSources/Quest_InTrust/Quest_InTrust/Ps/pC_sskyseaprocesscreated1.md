#### Parser Content
```Java
{
Name = s-skysea-process-created-1
    DataType = "process-created"
    Conditions = [ ",クライアント操作," ]
    Fields = ${SKySeaParserTemplates.s-skysea-dlp.Fields} [
      """^([^\,]{0,2000}\,){4}({session_id}\d)\,""",
      """^([^\,]{0,2000}\,){11}({process_name}[^\,]{1,2000})\,""",
      """^([^\,]{0,2000}\,){12}\s{0,100}({file_name}[^\,]{1,2000}?)\s{0,100}\,""",
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