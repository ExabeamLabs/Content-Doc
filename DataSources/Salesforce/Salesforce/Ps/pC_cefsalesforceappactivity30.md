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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",  
    """destinationServiceName=({host}.+?)\s{0,100}(\w+=|$)""",
    """destinationServiceName=({app}.+?)\s{0,100}(\w+=|$)""",
    """CreatedDate\\=({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """CreatedBy\.Username\\=({user_email}[^@]{1,2000}@({email_domain}[^\s;]{1,2000}))""",
    """Display\\=({additional_info}Created new user ({object}.+?))\s{0,100}(\w+=|$)""",
  ]
  DupFields = [ "user_email->user" ]
}
```