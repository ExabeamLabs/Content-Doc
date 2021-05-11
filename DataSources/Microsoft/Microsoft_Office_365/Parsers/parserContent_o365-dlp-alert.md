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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """Host Name:\s{0,100}({host}[^\s\\]+)""",
    """({event_name}DlpRuleMatch)""",
    """"CreationTime"{1,20}:\s{0,100}"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"From"{1,20}:\s{0,100}"{1,20}({user_email}[^@]+?@.+?)"""",
    """"To"{1,20}:\s{0,100}\[({recipients}({recipient}[^,]+)[^\]]*)\],""",
    """"BCC"{1,20}:\s{0,100}\[({bcc}[^\]]+)""",
    """"CC"{1,20}:\s{0,100}\[({cc}[^\]]+)""",
    """"PolicyName"{1,20}:\s{0,100}"{1,20}({alert_type}.*?[^"])"""",
    """"Subject"{1,20}:\s{0,100}"{1,20}({subject}.+?)\s{0,100}"{1,20}
```