#### Parser Content
```Java
{
Name = f5-dlp-email-out
  DataType = "dlp-email-alert"
  Conditions = [ """"log_type":"WAF"""", """"log_vendor":"f5"""", """ sSMTP[""", """]: Sent mail""" ]
  Fields = ${F5ParserTemplates.f5-waf-activity.Fields} [
    """Sent mail for ({sender}[^\s]{1,2000})""",
    """outbytes=({bytes}\d{1,100})""",
    """uid=({email_id}[^\s]{1,2000})""",
    """username=({user}[^\s]{1,2000})"""
  ]
  DupFields = [ "sender->user_email"]

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