#### Parser Content
```Java
{
Name = cef-unix-local-logon-2
  DataType = "local-logon"
  Conditions = [ """CEF""", """Unix|Unix""", """|VMCACheckAccessKrb: Authenticated user""" ]
  Fields = ${UnixParserTemplates.cef-unix-template.Fields}[
    """VMCACheckAccessKrb: Authenticated user ({user}[^\.\s@]+)(\.({domain}[^\|\s]+))?"""
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