#### Parser Content
```Java
{
Name = mcafee-security-alert-1027
  Vendor = McAfee
  Product = Mcafee EPO
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """EPOEvents""", """<EventID>1027""", """MachineName>""" ]
  Fields = [
    """\d{1,100}\s{1,100}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\S*\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}\w+""",
    """<MachineName>({src_host}[^<]{1,2000})<\/MachineName>""",
    """<IPAddress>({src_ip}[^<]{1,2000})<\/IPAddress>""",
    """<UserName>({domain}[^\\]{1,2000})\\({user}[^<]{1,2000})<\/UserName>""",
    """<EventID>({event_code}[^<]{1,2000})<\/EventID>""",
    """<Severity>({alert_severity}[^<]{1,2000})<\/Severity>""",
    """<FileName>({file_parent}[^<]{1,2000}[\\\/]{1,2000})({file_name}[^<]{1,2000}?\.({file_ext}[^<]{1,2000})?)""",
    """<szVirusType>({alert_type}[^<]{1,2000})<\/szVirusType>""",
    """<MD5>({md5}[^<]{1,2000})<\/MD5>""",
  ]
  DupFields = ["alert_type->alert_name"]
 }
```