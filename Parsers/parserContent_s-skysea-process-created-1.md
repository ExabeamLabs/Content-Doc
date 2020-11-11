#### Parser Content
```Java
{
Name = s-skysea-process-created-1
    DataType = "process-created"
    Conditions = [ ",????????????????????????," ]
    Fields = ${SKySeaParserTemplates.s-skysea-dlp.Fields} [
      """^([^\,]*\,){4}({session_id}\d)\,""",
      """^([^\,]*\,){11}({process_name}[^\,]+)\,""",
      """^([^\,]*\,){12}\s*({file_name}[^\,]+?)\s*\,""",
      """^([^\,]*\,){8}({activity_type}[^\,]+)\,"""
    ]
  }
```