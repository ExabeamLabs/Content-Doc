#### Parser Content
```Java
{
Name = cef-o365-dlp-alert
  Vendor = Microsoft
  Product = Office 365
  Lms = Direct
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """"Operation":"DlpRuleMatch"""" , """destinationServiceName=Office 365"""]
  Fields = [
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"CreationTime":"({time}\d\d\d\d-\d\d-\d\d\s{0,100}\d\d:\d\d:\d\d\.\d\d\d)"""",
    """"FromPerson":"({user_email}[^\@]{1,2000}\@[^"]{1,2000})"""",
    """"Id":"({user_id}[^"]{1,2000})"""", 
    """({alert_type}DlpRuleMatch)""",
    """"PolicyName":"({alert_name}[^"]{1,2000})"""",
    """"ToPerson":"({recipient}[^\@]{1,2000}\@[^"]{1,2000})"""",
    """"RuleName":"({additional_info}[^"]{1,2000})"""", 
    """"Location":"(Message Body|({file_name}[^"]{1,2000}))"""",
    """"IncidentId":"({alert_id}[^"]{1,2000})"""",
    """"Severity":"({alert_severity}[^"]{1,2000})"""",
  ]
  DupFields = [ "recipient->target", "alert_name->event_name" ]
}
}
```