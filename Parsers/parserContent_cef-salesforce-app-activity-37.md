#### Parser Content
```Java
{
Name = cef-salesforce-app-activity-37
  Vendor = Salesforce
  Product = Salesforce
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """Action\=unlockeduser;""", """Sales Cloud""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",  
    """CreatedDate\\=({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """CreatedBy\.Username\\=({user_email}[^@]+@({email_domain}[^\s;]+))""",
    """Action\\=({activity}[^;]+)""",
    """Display\\=Unlocked user ({object}.+?)\s*(\w+=|$)""",
    """\Wmsg=({additional_info}.+?)\s+(\w+=|$)""",
    """({app}Sales Cloud)"""
  ]
  DupFields = [ "user_email->user" ]
}
```