#### Parser Content
```Java
{
Name = unix-process-created-1
  DataType = "process-created"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"type":"SYSCALL"""", """success\=yes""", """Cloud Apps Security|""", """|audit-event|""" ]
  Fields = ${UnixParserTemplates.unix-template.Fields}[
    """\spid\\?=({pid}[^\s]{1,2000})\s\w+""",
    """ppid\\?=({parent_process_id}[^\s]{1,2000})\s{1,100}\w+""",
    """exe\\?=\\?"({command_line}[^"]{1,2000})""",
    """\ssuccess\\?=({outcome}[^\s]{1,2000})\s\w+"""
  ]	

unix-template = {
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
    
}
```