#### Parser Content
```Java
{
Name = cef-salesforce-app-activity-1
  Vendor = Salesforce
  Product = Salesforce
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """Action\=accountlayout;""", """Sales Cloud""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",  
    """CreatedDate\\=({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """CreatedBy\.Username\\=({user_email}[^@]{1,2000}@({email_domain}[^\s;]{1,2000}))""",
    """Action\\=({activity}[^;]{1,2000})""",
    """Display\\=({additional_info}.+?)\s{0,100}(\w+=|$)""",
    """Display\\=Changed Account page layout ({object}.+?)\s{0,100}(\w+=|$)""",
    """({app}Sales Cloud)""",
  ]
}
```