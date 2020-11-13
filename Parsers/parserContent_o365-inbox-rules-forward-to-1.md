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
    """exabeam_host=({host}[^\s]+)""",
    """"ResultStatus":"({outcome}[^"]+)"""",
    """"ClientIP":"(\[)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\])?(:({src_port}\d+))?""",
    """UserId":"({user_email}[^"\\]+@({user_domain}[^"]+))""",
    """"ActionType":"({activity}[^"]+)"""",
    """destinationServiceName=({app}[^=]+?)\s+\w+=""",
    """"SubjectOrBodyContainsWords":"({filter_key_words}[^"]+)""",
    """flexString1=({event_name}[^=]+?)\s+\w+=""",
    """Forward.+?Recipients\\?":\[?\\?"({target}[^\@]+@({target_domain}[^",;\\]+))"""
  ]
  DupFields = ["user_domain->email_domain"]
}
```