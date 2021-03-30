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
cef-unix-template = {
    Vendor = Unix
    Product = Unix Auditd
    Lms = Direct
    TimeFormat = epoch
    Fields = [
      """\Wrt=({time}\d+)""",
      """\Wdvc=({host}[^\s]+)""",
      """\Wdvchost=({host}[^\s]+)""",
      """CEF:([^\|]*\|){4}({additional_info}[^\|]+)""",
      """CEF:([^\|]*\|){5}({event_code}[^\|]+)""",
      """CEF:([^\|]*\|){6}({alert_severity}[^\|]+)""",
      """\WeventId=({alert_id}\d+)""",
      """\Wsuser=({user}[^\s]+)""",
      """\Wdhost=({dest_host}[\w\-.]+)""",
    ]

```