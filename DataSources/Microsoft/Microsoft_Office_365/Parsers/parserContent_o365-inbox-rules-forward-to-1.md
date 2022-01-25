#### Parser Content
```Java
{
Name = o365-inbox-rules-forward-to-1
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [""""UpdateInboxRules"""" , """"ActionType":"Forward"""","""destinationServiceName=""" ]
  Fields = [
    """"CreationTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"ResultStatus":"({outcome}[^"]{1,2000})"""",
    """"ClientIP":"(\[)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\])?(:({src_port}\d{1,100}))?""",
    """UserId":"({user_email}[^"\\]{1,2000}@({user_domain}[^"]{1,2000}))""",
    """"ActionType":"({activity}[^"]{1,2000})"""",
    """destinationServiceName=({app}[^=]{1,2000}?)\s{1,100}\w+=""",
    """"SubjectOrBodyContainsWords":"({filter_key_words}[^"]{1,2000})""",
    """flexString1=({event_name}[^=]{1,2000}?)\s{1,100}\w+=""",
    """Forward.+?Recipients\\?":\[?\\?"({target}[^\@]{1,2000}@({target_domain}[^",;\\]{1,2000}))"""
  ]
  DupFields = ["user_domain->email_domain"]
}
```