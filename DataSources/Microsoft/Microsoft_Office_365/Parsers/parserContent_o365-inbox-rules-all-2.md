#### Parser Content
```Java
{
Name = o365-inbox-rules-all-2
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = ["""Operation":"Set-InboxRule""" ]
  Fields = [
    """"CreationTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""",
    """Forward.+?Value":"(smtp:)?({target}[^"]{1,2000}@({target_domain}[^"]{1,2000}))""""
    """"ResultStatus":"({outcome}[^"]{1,2000})"""",
    """"ClientIP":"({src_ip}[^:]{1,2000}):""",
    """({activity}Set-Mailbox)""",
    """cs1=(\[\{"additional-properties"\:)?\{"({activity}[^"]{1,2000})""",
    """msg=({additional_info}.+?)\s\w+=""",
    """"Value":"(?:smtp:)?.+?@({target_domain}[^"]{1,2000})"""",
    """UserId":"({user_email}[^"\\]{1,2000}@({user_domain}[^"]{1,2000})[^"]{1,2000})"""",
    """UserId":"(\\.+)?\/({user_fullname}[^,\\"]{1,2000})\\"\s{0,100}on behalf""",
    """UserId":"(\\.+)?\/({user_lastname}[^,]{1,2000}),\s{0,100}({user_firstname}[^\\"]{1,2000})\\"\s{0,100}on behalf""",
    """UserId":"({user_email}[^"\\]{1,2000}@({user_domain}[^"]{1,2000})[^"]{1,2000})"""",   
    """destinationServiceName=({app}.+?)\s{0,100}filePath"""
    """({app}Office 365)"""
    """"SubjectOrBodyContainsWords":"({filter_key_words}[^"]{1,2000})"""
  ]
  DupFields = ["user_domain->email_domain"]
}
```