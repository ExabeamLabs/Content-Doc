#### Parser Content
```Java
{
Name = cef-salesforce-app-activity-29
  Vendor = Salesforce
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """Action\=profileFlsChangedStandard""", """Sales Cloud""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",  
    """CreatedDate\\=({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)"""
    """CreatedBy\.Username\\=({user_email}[^\s;]+)""",
    """suser=({user}.+?)\s+(\w+=|$)""",
    """suser=({user_email}[^@\s]+?@[^@\s]+)\s*(\w+=|$)""",
    """Action\\=({activity}[^;]+)""",
    """Display\\=({additional_info}.+?)\s*(\w+=|$)""",
    """Display\\=Change.*?:\s*({object}[^:]+?)\s+was changed""",
    """({app}Sales Cloud)""",
  ]
}
```