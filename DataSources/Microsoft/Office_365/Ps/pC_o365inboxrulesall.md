#### Parser Content
```Java
{
Name = o365-inbox-rules-all
  Vendor = Microsoft
  Product = Office 365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = ["""New-InboxRule""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """time="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """host="({host}[^"]{1,2000})"""",
    """"CreationTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""",
    """"Name":"ForwardTo".+?"Value":"(?:smtp:)?({target}[^"]{1,2000})""""
    """"ResultStatus":"({outcome}[^"]{1,2000})"""",
    """"ClientIP":"({src_ip}[^:]{1,2000}):""",
    """({activity}New-InboxRule)"""
    """cs1=(\[\{"additional-properties"\:)?\{"({activity}[^"]{1,2000})""",
    """msg=({additional_info}.+?)\s\w+=""",
    """user="({user}[^"]{1,2000})""",
    """user_email="({user_email}[^@"]{1,2000}@[^\."]{1,2000}\.[^"]{1,2000})"""",
    """"Value":"(?:smtp:)?.+?@({target_domain}[^"]{1,2000})"""",
    """UserId":"({user}.+?@({user_domain}[^"]{1,2000}).+?)""",
    """destinationServiceName =({app}.+?)\s{0,100}filePath""",
    """({app}Office 365)"""
    """"SubjectOrBodyContainsWords":"({filter_key_words}[^"]{1,2000})"""
  ]


}
```