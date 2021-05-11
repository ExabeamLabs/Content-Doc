#### Parser Content
```Java
{
Name = unix-process-created-failed
  DataType = "process-created-failed"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"type":"SYSCALL"""", """success\=no""", """CEF:""", """|Skyformation|SkyFormation""", """Cloud Apps Security|""", """|audit-event|""" ]
  Fields = ${UnixParserTemplates.unix-template.Fields}[
    """ppid\\?=({parent_process_id}[^\s]+)\s{1,100}\w+""",
    """\spid\\?=({pid}[^\s]+)\s\w+""",
    """\sgid\\?=({group_id}[^\s]+)\s\w+""",
    """type"{1,20}:"{1,20}({event_name}[^"]+)""""
  ]
}
unix-template = {
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