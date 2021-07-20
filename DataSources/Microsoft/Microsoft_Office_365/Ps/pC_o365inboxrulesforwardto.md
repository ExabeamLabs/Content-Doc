#### Parser Content
```Java
{
Name = o365-inbox-rules-forward-to
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = ["""New-InboxRule""" , """ForwardTo""" ]
  Fields = [
    """"CreationTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""",
    """Forward.+?Value":"(smtp:)?({target}[^"]{1,2000}@({target_domain}[^"]{1,2000}))""""
    """"ResultStatus":"({outcome}[^"]{1,2000})"""",
    """"ClientIP":"({src_ip}[^:]{1,2000}):""",
    """({activity}ForwardTo)"""",
    """msg=({additional_info}.+?)\srequest=""",
    """UserId":"({user_email}[^"\\]{1,2000}@({user_domain}[^"]{1,2000}))""",
    """destinationServiceName=({app}.+?)\s(device|filePath)""",
    """({app}Office 365)"""
    """"SubjectOrBodyContainsWords":"({filter_key_words}[^"]{1,2000})"""
  ]
  DupFields = ["user_domain->email_domain"]
}
```