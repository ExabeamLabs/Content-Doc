#### Parser Content
```Java
{
Name = o365-security-alert-2
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Splunk
  DataType = "security-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions =[""""event-name":"security-threat-detected"""", """Severity":"""", """"src-application-name":"Office 365"""", """Operation"""]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """CreationTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """Operation"{0,20}:\s{0,100}"{1,20}({activity}[^"]{1,2000})"""",
    """"ObjectId":"({user_email}[^@]{1,2000}@[^",]{1,2000})","""",
    """"f3u\\?":\\?"({user_email}[^@]{1,2000}@[^",]{1,2000}?)\\?"""",
    """"result":"({outcome}[^"]{1,2000})""",
    """"Category":"({category}[^"]{1,2000})""",
    """"Severity":"({alert_severity}[^"]{1,2000})""",
    """"Source":"({additional_info}[^"]{1,2000})""",
    """"Status":"({status}[^"]{1,2000})""",
    """"category":"({alert_type}[^"]{1,2000})""",
    """"action":"({alert_name}[^"]{1,2000})""",
    """"src-account-name":"({account}[^"]{1,2000})""",
    """Workload":"({app}[^"]{1,2000})""",
    """"id":({alert_id}\d{1,100})"""
  ]


}
```