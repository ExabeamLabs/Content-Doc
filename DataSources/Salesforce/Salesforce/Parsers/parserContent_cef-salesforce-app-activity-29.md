#### Parser Content
```Java
{
Name = cef-salesforce-app-activity-29
  Vendor = Salesforce
  Product = Salesforce
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """Action\=profileFlsChangedStandard""", """Sales Cloud""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",  
    """CreatedDate\\=({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)"""
    """CreatedBy\.Username\\=({user_email}[^@]{1,2000}@({email_domain}[^\s;]{1,2000}))""",
    """suser=({user}.+?)\s{1,100}(\w+=|$)""",
    """suser=({user_email}[^@\s]{1,2000}?@[^@\s]{1,2000})\s{0,100}(\w+=|$)""",
    """Action\\=({activity}[^;]{1,2000})""",
    """Display\\=({additional_info}.+?)\s{0,100}(\w+=|$)""",
    """Display\\=Change.*?:\s{0,100}({object}[^:]{1,2000}?)\s{1,100}was changed""",
    """({app}Sales Cloud)""",
  ]
}
```