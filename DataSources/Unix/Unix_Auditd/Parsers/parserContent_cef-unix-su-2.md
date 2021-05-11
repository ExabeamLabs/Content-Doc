#### Parser Content
```Java
{
Name = cef-unix-su-2
  DataType = "unix-account-switch"
  Conditions = [ """CEF""", """Unix|Unix""", """|session closed|""" ]
  Fields = ${UnixParserTemplates.cef-unix-template.Fields}[
     """\sduser=({account}.*?)\s{1,100}\w+="""
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