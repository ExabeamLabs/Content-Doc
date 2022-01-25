#### Parser Content
```Java
{
Name = s-postfix-dlp-email
  Vendor = Postfix
  Product = Postfix
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """postfix""", """header Subject:""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d ({host}\S+) postfix[^:]{1,2000}:\s{0,100}({msg_id}[^\s:]{1,2000})""",
    """\WSubject:\s{0,100}({subject}[^;]{1,2000})""",
    """\Wfrom=<({sender}[^\s\>]{1,2000})""",
    """\Wto=<({recipients}[^\>]{1,2000})""",
    """\Wto=<({recipient}[^\s\>,;]{1,2000})""",
    """\Wfrom (unknown|({src_host}[\w\-.]{1,2000}))\[({src_ip}[a-fA-F:\d.]{1,2000})""",
  ]


}
```