#### Parser Content
```Java
{
Name = cef-aix-process-created
  DataType = "process-created"
  Conditions = [ """CEF""", """Unix|Unix""", """|CMD|""" ]
  Fields = ${UnixParserTemplates.cef-unix-template.Fields}[
    """\sfname=({command_line}.*?)\s{1,100}\w+="""
    """\sfname=({process}({directory}\/.*?)({process_name}[^\/]{0,2000}?[^\\]))((\\\\)*\s|\))"""
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
      """\Wdvc=({host}[^\s]{1,2000})""",
      """\Wdvchost=({host}[^\s]{1,2000})""",
      """CEF:([^\|]{0,2000}\|){4}({additional_info}[^\|]{1,2000})""",
      """CEF:([^\|]{0,2000}\|){5}({event_code}[^\|]{1,2000})""",
      """CEF:([^\|]{0,2000}\|){6}({alert_severity}[^\|]{1,2000})""",
      """\WeventId=({alert_id}\d{1,100})""",
      """\Wsuser=({user}[^\s]{1,2000})""",
      """\Wdhost=({dest_host}[\w\-.]{1,2000})""",
    ]

```