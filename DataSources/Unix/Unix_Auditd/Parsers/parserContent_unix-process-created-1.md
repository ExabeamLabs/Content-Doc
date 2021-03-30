#### Parser Content
```Java
{
Name = unix-process-created-1
  DataType = "process-created"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"type":"SYSCALL"""", """success\=yes""", """CEF:""", """|Skyformation|SkyFormation""", """Cloud Apps Security|""", """|audit-event|""" ]
  Fields = ${UnixParserTemplates.unix-template.Fields}[
    """\spid\\?=({pid}[^\s]+)\s\w+""",
    """ppid\\?=({parent_process_id}[^\s]+)\s+\w+""",
    """exe\\?=\\?"({command_line}[^"]+)""",
    """\ssuccess\\?=({outcome}[^\s]+)\s\w+"""
  ]	
}
unix-template = {
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