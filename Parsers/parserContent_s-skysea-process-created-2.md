#### Parser Content
```Java
{
Name = s-skysea-process-created-2
    DataType = "process-created"
    Conditions = [ ",????????????????????????," ]
    Fields = ${SKySeaParserTemplates.s-skysea-dlp.Fields} [
      """^([^\,]*\,){4}({session_id}\d)\,""",
      """^([^\,]*\,){69}({md5}[^\,]+)\,""",
      """^([^\,]*\,){68}({process}({directory}(?:(\w+:)*([\\\/]+[^\\\/"]+)+)?[\\\/]+)({process_name}.+?))\,""",
      """^([^\,]*\,){8}({activity_type}[^\,]+)\,"""
    ]
  }
```