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
    """Forward.+?Value":"(smtp:)?({target}[^"]+@({target_domain}[^"]+))""""
    """"ResultStatus":"({outcome}[^"]+)"""",
    """"ClientIP":"({src_ip}[^:]+):""",
    """({activity}Set-Mailbox)""",
    """cs1=(\[\{"additional-properties"\:)?\{"({activity}[^"]+)""",
    """msg=({additional_info}.+?)\s\w+=""",
    """"Value":"(?:smtp:)?.+?@({target_domain}[^"]+)"""",
    """UserId":"({user_email}[^"\\]+@({user_domain}[^"]+)[^"]+)"""",
    """UserId":"(\\.+)?\/({user_fullname}[^,\\"]+)\\"\s{0,100}on behalf""",
    """UserId":"(\\.+)?\/({user_lastname}[^,]+),\s{0,100}({user_firstname}[^\\"]+)\\"\s{0,100}on behalf""",
    """UserId":"({user_email}[^"\\]+@({user_domain}[^"]+)[^"]+)"""",   
    """destinationServiceName=({app}.+?)\s{0,100}filePath"""
    """({app}Office 365)"""
    """"SubjectOrBodyContainsWords":"({filter_key_words}[^"]+)"""
  ]
  DupFields = ["user_domain->email_domain"]
}
```