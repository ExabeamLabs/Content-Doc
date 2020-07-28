#### Parser Content
```Java
{
Name = cef-aix-process-created
  DataType = "process-created"
  Conditions = [ """CEF""", """Unix|Unix""", """|CMD|""" ]
  Fields = ${UnixParserTemplates.cef-unix-template.Fields}[
    """\sfname=({command_line}.*?)\s+\w+="""
    """\sfname=({process}({directory}\/.*?)({process_name}[^\/]*?[^\\]))((\\\\)*\s|\))"""
    """\Wcs4=({pid}\d+)"""
  ]
}
```