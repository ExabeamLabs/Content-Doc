#### Parser Content
```Java
{
Name = cef-salesforce-app-activity-30
  Vendor = Salesforce
  Product = Salesforce
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """Action\=createduser;""", """Sales Cloud""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",  
    """destinationServiceName=({host}.+?)\s*(\w+=|$)""",
    """destinationServiceName=({app}.+?)\s*(\w+=|$)""",
    """CreatedDate\\=({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """CreatedBy\.Username\\=({user_email}[^@]+@({email_domain}[^\s;]+))""",
    """Display\\=({additional_info}Created new user ({object}.+?))\s*(\w+=|$)""",
  ]
  DupFields = [ "user_email->user" ]
}
```