#### Parser Content
```Java
{
Name = o365-dlp-alert
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = QRadar
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """DlpRuleMatch""", """"From"""", """"RuleName"""", """"PolicyName"":"""" ]
  Fields =[
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """Host Name:\s{0,100}({host}[^\s\\]{1,2000})""",
    """({event_name}DlpRuleMatch)""",
    """"CreationTime"{1,20}:\s{0,100}"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"From"{1,20}:\s{0,100}"{1,20}({user_email}[^@]{1,2000}?@.+?)"""",
    """"To"{1,20}:\s{0,100}\[({recipients}({recipient}[^,]{1,2000})[^\]]{0,2000})\],""",
    """"BCC"{1,20}:\s{0,100}\[({bcc}[^\]]{1,2000})""",
    """"CC"{1,20}:\s{0,100}\[({cc}[^\]]{1,2000})""",
    """"PolicyName"{1,20}:\s{0,100}"{1,20}({alert_type}.*?[^"])"""",
    """"Subject"{1,20}:\s{0,100}"{1,20}({subject}.+?)\s{0,100}"{1,20}
```