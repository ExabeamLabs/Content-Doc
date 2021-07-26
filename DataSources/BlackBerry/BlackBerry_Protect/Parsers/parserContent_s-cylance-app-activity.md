#### Parser Content
```Java
{
Name = s-cylance-app-activity
  Vendor = BlackBerry
  Product = BlackBerry Protect
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """, Event Name:""", """, Message:""", """Event Type: AuditLog""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)[^\s]{0,2000}\s{1,100}[^\s]{1,2000}\s{1,100}({app}[^\s]{1,2000})\s""",
    """\w+\s{1,100}\d{1,100} \d\d:\d\d:\d\d ({host}[a-fA-F\d.:]{1,2000})""",
    """\[({host}[\w\-.]{1,2000})\]\s{0,100}Event Type:""",
    """\sEvent Name:\s{0,100}({activity}[^,]{1,2000}),""",
    """\sMessage:.+?[^,:]{1,2000}(Assigned|Changed):\s{0,100}({additional_info}[^:,;]{1,2000})""",
    """\sUser:\s{0,100}(|({user_fullname}.+?))\s{0,100}\(({user_email}[^@\s\)]{1,2000}@({email_domain}[^@\s\)]{1,2000}))\)""",
    """\sSource IP:\s{0,100}({src_ip}[a-fA-F\d\.:]{1,2000})""",
    """\sProvider:\s{0,100}({login_type}[^,]{1,2000})""",
    """\sDevice:\s{0,100}({object}[^;]{1,2000})""",
  ]
  DupFields = [ "host->dest_host" ]
}
```