#### Parser Content
```Java
{
Name = o365-inbox-rules-forward-to
  Vendor = Microsoft
  Product = Office 365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = ["""New-InboxRule""" , """ForwardTo""" ]
  Fields = [
    """"CreationTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""",
    """Forward.+?Value":"(smtp:)?({target}[^"]+@({target_domain}[^"]+))""""
    """"ResultStatus":"({outcome}[^"]+)"""",
    """"ClientIP":"({src_ip}[^:]+):""",
    """({activity}ForwardTo)"""",
    """msg=({additional_info}.+?)\srequest=""",
    """UserId":"({user_email}[^"\\]+@({user_domain}[^"]+))""",
    """destinationServiceName=({app}.+?)\s(device|filePath)""",
    """({app}Office 365)"""
  ]
  DupFields = ["user_domain->email_domain"]
}
```