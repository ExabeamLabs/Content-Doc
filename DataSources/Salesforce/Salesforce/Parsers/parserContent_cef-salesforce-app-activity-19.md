#### Parser Content
```Java
{
Name = cef-salesforce-app-activity-19
  Vendor = Salesforce
  Product = Salesforce
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """Action\=profileOlpChangedCustom;""", """Sales Cloud""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",  
    """CreatedDate\\=({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """CreatedBy\.Username\\=({user_email}[^@]+({email_domain}[^\s;]+))""",
    """Action\\=({activity}[^;]+)""",
    """Display\\=({additional_info}.+?)\s{0,100}(\w+=|$)""",
    """Display\\=Changed profile ({object}.+?): ({resource}.+?) object""",
    """({app}Sales Cloud)""",
  ]
}
```