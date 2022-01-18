#### Parser Content
```Java
{
Name = unix-process-created-failed
  DataType = "process-created-failed"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"type":"SYSCALL"""", """success\=no""", """CEF:""", """|Skyformation|SkyFormation""", """Cloud Apps Security|""", """|audit-event|""" ]
  Fields = ${UnixParserTemplates.unix-template.Fields}[
    """ppid\\?=({parent_process_id}[^\s]{1,2000})\s{1,100}\w+""",
    """\spid\\?=({pid}[^\s]{1,2000})\s\w+""",
    """\sgid\\?=({group_id}[^\s]{1,2000})\s\w+""",
    """type"{1,20}:"{1,20}({event_name}[^"]{1,2000})""""
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