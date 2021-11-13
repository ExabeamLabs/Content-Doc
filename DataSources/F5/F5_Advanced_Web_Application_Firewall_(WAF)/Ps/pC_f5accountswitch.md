#### Parser Content
```Java
{
Name = f5-account-switch
  DataType = "account-switch"
  Conditions = [ """"log_type":"WAF"""", """"log_vendor":"f5"""", """session opened for user""", """(uid=""", """sshd:""", """_unix""" ]
  Fields = ${F5ParserTemplates.f5-waf-activity.Fields} [
    """\(uid=({user_uid}\d{1,100})\)""",
    """session opened for user ({account}[^\s]{1,2000}) by""",
    """sshd\[({logon_id}\d{1,100})""",
    """({event_code}ssh)""",
  ]

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
    
}
```