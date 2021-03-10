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
```