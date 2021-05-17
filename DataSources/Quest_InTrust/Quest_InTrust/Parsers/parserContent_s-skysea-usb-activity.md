#### Parser Content
```Java
{
Name = s-skysea-usb-activity
    DataType = "usb-activity"
    Conditions = [ """,ドライブ,""", """,ドライブの追加,""" ]
    Fields = ${SKySeaParserTemplates.s-skysea-dlp.Fields} [
    """({host}[^,]{1,2000}),([^,]{0,2000}
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