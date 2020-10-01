#### Parser Content
```Java
{
Name = cef-salesforce-app-activity-23
  Vendor = Salesforce
  Product = Salesforce
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """Action\=SetupEntityAccessAudit_Profile_ConnectedApplication_DisabledCustom;""", """Sales Cloud""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",  
    """CreatedDate\\=({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """CreatedBy\.Username\\=({user_email}[^@]+@({email_domain}[^\s;]+))""",
    """Action\\=({activity}[^;]+)""",
    """Display\\=({additional_info}.+?)\s*(\w+=|$)""",
    """Display\\=Changed profile ({object}.+?): ({resource}.+?) connected""",
    """({app}Sales Cloud)""",
  ]
}
```