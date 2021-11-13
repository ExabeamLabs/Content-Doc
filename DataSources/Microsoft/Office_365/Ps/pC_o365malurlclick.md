#### Parser Content
```Java
{
Name = o365-mal-url-click
  Vendor = Microsoft
  Product = Office 365
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"Operation":"AlertEntityGenerated"""", """"UserKey":"SecurityComplianceAlerts"""", """MaliciousUrlClick""" ]
  Fields = [
    """"CreationTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"Operation":"({activity}[^"]{0,2000})"""",
    """requestClientApplication=({app}[^=]{1,2000})\s{1,100}(\w+=|$)""",
    """"AlertEntityId":"({malware_url}[^"]{1,2000})"""",
    """"ResultStatus":"({outcome}[^"]{1,2000})"""",
    """"Category":"({category}[^"]{1,2000})"""",
    """"AlertType":"({alert_type}[^"]{1,2000})"""",
    """"Severity":"({alert_severity}[^"]{1,2000})"""",
    """"Name":"({alert_name}[^"]{1,2000})"""",
    """"trc\\":\\"({user_email}[^"\s@]{1,2000}@[^"\s@\\]{1,2000})\\"""",
    """"AlertId":"({alert_id}[^"]{1,2000})"""",
  ]


}
```