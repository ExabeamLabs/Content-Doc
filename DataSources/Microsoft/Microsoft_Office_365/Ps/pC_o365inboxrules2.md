#### Parser Content
```Java
{
Name = o365-inbox-rules-2
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = ["""Operation":"Set-Mailbox""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"CreationTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""",
    """Forward[^\}]{1,2000}?Value":"(smtp:)?({target}[^"]{1,2000}@({target_domain}[^"]{1,2000}))""""
    """"ResultStatus":"({outcome}[^"]{1,2000})"""",
    """"ClientIP":"\[?({src_ip}[^"]{1,2000}?)\]?:({src_port}\d{1,100})"""",
    """({activity}Set-Mailbox)""",
    """cs1=(\[\{"additional-properties"\:)?\{"({activity}[^"]{1,2000})""",
    """msg=({additional_info}[^=]{1,2000}?)\s\w+=""",
    """"Value":"(?:smtp:)?[^@]{1,2000}?@({target_domain}[^;"]{1,2000})"""",
    """UserId":"({user_email}[^"\\\s@]{1,2000}@({user_domain}[^"\\\s@]{1,2000}))""",
    """destinationServiceName =({app}[^=]{1,2000}?)\s{0,100}filePath"""
    """({app}Office 365)"""
  ]
  DupFields = ["user_domain->email_domain"]


}
```