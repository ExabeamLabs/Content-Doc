#### Parser Content
```Java
{
Name = o365-inbox-rules-2
  Vendor = Microsoft
  Product = Office 365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = ["""Operation":"Set-Mailbox""" ]
  Fields = [
    """"CreationTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""",
    """Forward.+?Value":"(smtp:)?({target}[^"]+@({target_domain}[^"]+))""""
    """"ResultStatus":"({outcome}[^"]+)"""",
    """"ClientIP":"\[?({src_ip}[^"]+?)\]?:({src_port}\d+)"""",
    """({activity}Set-Mailbox)""",
    """cs1=(\[\{"additional-properties"\:)?\{"({activity}[^"]+)""",
    """msg=({additional_info}.+?)\s\w+=""",
    """"Value":"(?:smtp:)?.+?@({target_domain}[^"]+)"""",
    """UserId":"({user_email}[^"\\\s@]+@({user_domain}[^"\\\s@]+))""",
    """destinationServiceName=({app}.+?)\s*filePath"""
    """({app}Office 365)"""
  ]
  DupFields = ["user_domain->email_domain"]
}
```