#### Parser Content
```Java
{
Name = cef-unix-ssh-fail
  DataType = "ssh-login"
  Conditions = [ """CEF""", """Unix|Unix""", """|failed login attempt|""" ]
  Fields = ${UnixParserTemplates.cef-unix-template.Fields}[
     """\sduser=({user}.*?)\s{1,100}\w+="""
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