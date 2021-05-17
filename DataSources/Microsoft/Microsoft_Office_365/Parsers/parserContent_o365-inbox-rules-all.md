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
    """"Name":"ForwardTo".+?"Value":"(?:smtp:)?({target}[^"]{1,2000})""""
    """"ResultStatus":"({outcome}[^"]{1,2000})"""",
    """"ClientIP":"({src_ip}[^:]{1,2000}):""",
    """({activity}New-InboxRule)"""
    """cs1=(\[\{"additional-properties"\:)?\{"({activity}[^"]{1,2000})""",
    """msg=({additional_info}.+?)\s\w+=""",
    """"Value":"(?:smtp:)?.+?@({target_domain}[^"]{1,2000})"""",
    """UserId":"({user}.+?@({user_domain}[^"]{1,2000}).+?)""",
    """destinationServiceName=({app}.+?)\s{0,100}filePath""",
    """({app}Office 365)"""
    """"SubjectOrBodyContainsWords":"({filter_key_words}[^"]{1,2000})"""
  ]
}
```