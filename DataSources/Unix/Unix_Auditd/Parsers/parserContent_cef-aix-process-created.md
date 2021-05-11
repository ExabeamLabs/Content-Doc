#### Parser Content
```Java
{
Name = cef-aix-process-created
  DataType = "process-created"
  Conditions = [ """CEF""", """Unix|Unix""", """|CMD|""" ]
  Fields = ${UnixParserTemplates.cef-unix-template.Fields}[
    """\sfname=({command_line}.*?)\s{1,100}\w+="""
    """\sfname=({process}({directory}\/.*?)({process_name}[^\/]*?[^\\]))((\\\\)*\s|\))"""
    """\Wcs4=({pid}\d{1,100})"""
  ]
}
cef-unix-template = {
    Vendor = Unix
    Product = Unix Auditd
    Lms = Direct
    TimeFormat = epoch
    Fields = [
      """\Wrt=({time}\d{1,100})""",
      """\Wdvc=({host}[^\s]+)""",
      """\Wdvchost=({host}[^\s]+)""",
      """CEF:([^\|]*\|){4}({additional_info}[^\|]+)""",
      """CEF:([^\|]*\|){5}({event_code}[^\|]+)""",
      """CEF:([^\|]*\|){6}({alert_severity}[^\|]+)""",
      """\WeventId=({alert_id}\d{1,100})""",
      """\Wsuser=({user}[^\s]+)""",
      """\Wdhost=({dest_host}[\w\-.]+)""",
    ]

```