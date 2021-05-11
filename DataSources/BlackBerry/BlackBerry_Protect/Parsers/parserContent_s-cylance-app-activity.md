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
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)[^\s]*\s{1,100}[^\s]+\s{1,100}({app}[^\s]+)\s""",
    """\w+\s{1,100}\d{1,100} \d\d:\d\d:\d\d ({host}[a-fA-F\d.:]+)""",
    """\[({host}[\w\-.]+)\]\s{0,100}Event Type:""",
    """\sEvent Name:\s{0,100}({activity}[^,]+),""",
    """\sMessage:.+?[^,:]+(Assigned|Changed):\s{0,100}({additional_info}[^:,;]+)""",
    """\sUser:\s{0,100}(|({user_fullname}.+?))\s{0,100}\(({user_email}[^@\s\)]+@({email_domain}[^@\s\)]+))\)""",
    """\sSource IP:\s{0,100}({src_ip}[a-fA-F\d\.:]+)""",
    """\sProvider:\s{0,100}({login_type}[^,]+)""",
    """\sDevice:\s{0,100}({object}[^;]+)""",
  ]
  DupFields = [ "host->dest_host" ]
}
```