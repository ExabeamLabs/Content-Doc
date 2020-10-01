#### Parser Content
```Java
{
Name = o365-inbox-rules-all
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = ["""New-InboxRule""" ]
  Fields = [
    """"CreationTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""",
    """"Name":"ForwardTo".+?"Value":"(?:smtp:)?({target}[^"]+)""""
    """"ResultStatus":"({outcome}[^"]+)"""",
    """"ClientIP":"({src_ip}[^:]+):""",
    """({activity}New-InboxRule)"""
    """cs1=(\[\{"additional-properties"\:)?\{"({activity}[^"]+)""",
    """msg=({additional_info}.+?)\s\w+=""",
    """"Value":"(?:smtp:)?.+?@({target_domain}[^"]+)"""",
    """UserId":"({user}.+?@({user_domain}[^"]+).+?)""",
    """destinationServiceName=({app}.+?)\s*filePath""",
    """({app}Office 365)"""
  ]
}
```