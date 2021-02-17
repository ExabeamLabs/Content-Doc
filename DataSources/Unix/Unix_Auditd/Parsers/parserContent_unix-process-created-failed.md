#### Parser Content
```Java
{
Name = unix-process-created-failed
  DataType = "process-created-failed"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"type":"SYSCALL"""", """success\=no""", """CEF:""", """|Skyformation|SkyFormation""", """Cloud Apps Security|""", """|audit-event|""" ]
  Fields = ${UnixParserTemplates.unix-template.Fields}[
    """ppid\\?=({parent_process_id}[^\s]+)\s+\w+""",
    """\spid\\?=({pid}[^\s]+)\s\w+""",
    """\sgid\\?=({group_id}[^\s]+)\s\w+""",
    """type"+:"+({event_name}[^"]+)""""
  ]
}
```