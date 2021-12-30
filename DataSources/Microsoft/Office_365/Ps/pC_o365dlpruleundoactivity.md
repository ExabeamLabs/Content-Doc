#### Parser Content
```Java
{
Name = o365-dlp-rule-undo-activity
  Vendor = Microsoft
  Product = Office 365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"Workload":""", """"PolicyDetails":""", """"Operation":"DLPRuleUndo"""" ]
  Fields = [
    """exabeam_host=({host}[\w.-]{1,2000})""",
    """"CreationTime":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})"""",
    """"Workload":"({app}[^"]{1,2000})"""",
    """"ObjectId":"<?({object}[^"]{1,2000}?)>?"""",
    """"Operation":"({activity}[^"]{1,2000})"""",
    """"From":"({user_email}[^@"]{1,2000}@({email_domain}[^"]{1,2000}))"""",
    """"FileOwner":"({user_fullname}[^\s\/"]{1,2000}?\s{1,100}[^\/"]{1,2000}?)"""",
    """"Severity":"({alert_severity}[^"]{1,2000})"""",
    """"IncidentId":"({alert_id}[^"]{1,2000})"""",
    """"RuleName":"({event_name}[^"]{1,2000}?)"""",
    """"FileName":"({file_name}[^"]{1,2000}?)"""",
    """"PolicyName":"({policy}[^"]{1,2000})""",
    """"Reason":"({additional_info}[^"]{1,2000}?)""""
    ]


}
```