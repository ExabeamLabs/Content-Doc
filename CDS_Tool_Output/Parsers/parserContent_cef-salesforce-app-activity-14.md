#### Parser Content
```Java
{
Name = cef-salesforce-app-activity-14
  Vendor = Salesforce
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """Action\=passwordexpiryForProfile;""", """Sales Cloud""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",  
    """CreatedDate\\=({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """CreatedBy\.Username\\=({user_email}[^\s;]+)""",
    """Action\\=({activity}[^;]+)""",
    """Display\\=({additional_info}.+?)\s*(\w+=|$)""",
    """Display\\=Changed profile ({object}.+?): Changed ({resource}.+?) from """,
    """({app}Sales Cloud)""",
  ]
}
```