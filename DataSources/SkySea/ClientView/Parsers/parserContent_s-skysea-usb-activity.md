#### Parser Content
```Java
{
Name = s-skysea-usb-activity
    DataType = "usb-activity"
    Conditions = [ ",ドライブ," ]
    Fields = ${SKySeaParserTemplates.s-skysea-dlp.Fields} [
      """^([^\,]*\,){11}({target}[^\,]+)\,""",
      """^([^\,]*\,){24}({device_id}[^\,]+)\,""",
      """^([^\,]*\,){21}({device_name}[^\,]+)\,""",
      """^([^\,]*\,){17}({activity}[^\,]+)\,""",
      """^([^\,]*\,){38}({device_type}[^\,]+)\,""",

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