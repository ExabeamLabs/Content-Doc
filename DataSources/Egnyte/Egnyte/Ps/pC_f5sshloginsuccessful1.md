#### Parser Content
```Java
{
Name = f5-ssh-login-successful-1
  DataType = "ssh-login"
  Conditions = [ """"log_type":"WAF"""", """"log_vendor":"f5"""", """ssh""", """Accepted """, """ for """, """ from """ ]
  Fields = ${F5ParserTemplates.f5-waf-activity.Fields} [
    """Accepted ({auth_package}\S+) for (({domain}[^\\:]{1,2000})\\+)?({user}[\w.'\-\\$]{1,2000})(\s|$)""",
    """({event_code}ssh)""",
    """sshd\[({logon_id}\d{1,100})""",
    """SHA256:({sha256}[^"]{1,2000})""""
  ]
}
f5-waf-activity = {
    Vendor = F5
    Product = F5 Advanced Web Application Firewall (WAF)
    Lms = Direct
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Fields = [
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """exabeam_host=([^=]{1,2000}@\s{0,100})?(::ffff:)?({host}\S+)""",
      """"@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
      """"host":"(::ffff:)?({host}[^"]{1,2000})""",
      """\d\d:\d\d:\d\d ({host}[^\s]{1,2000}) \w+ \w+\["""
    ]}
```