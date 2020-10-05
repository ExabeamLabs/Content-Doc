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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """Host Name:\s*({host}[^\s\\]+)""",
    """({event_name}DlpRuleMatch)""",
    """"CreationTime"+:\s*"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"From"+:\s*"+({user_email}[^@]+?@.+?)"""",
    """"To"+:\s*\[({recipients}({recipient}[^,]+)[^\]]*)\],""",
    """"BCC"+:\s*\[({bcc}[^\]]+)""",
    """"CC"+:\s*\[({cc}[^\]]+)""",
    """"PolicyName"+:\s*"+({alert_type}.*?[^"])"""",
    """"Subject"+:\s*"+({subject}.+?)\s*"+,"+To"+:""",
    """"RuleName"+:\s*"+({alert_name}[^",]+)"""",
    """"Severity"+:\s*"+({alert_severity}[^"]+)"""",
    """"Actions"+:\s*\["+({action}[^"]+)"+\]""",
    """"RecipientCount"+:\s*({recipient_count}\d+)""",  
    """"IncidentId"+:\s*"+({alert_id}[^",]+)"""",
    """"Workload"+:\s*"+({app}[^",]+)"""
 ]
}
```