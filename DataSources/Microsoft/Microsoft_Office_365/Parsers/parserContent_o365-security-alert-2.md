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
    """exabeam_host=([^=]+@\s{0,100})?({host}[\w\-.]+)""",
    """CreationTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """Operation"{0,20}:\s{0,100}"{1,20}({activity}[^"]+)"""",
    """"ObjectId":"({user_email}[^@]+@[^",]+)","""",
    """"f3u\\?":\\?"({user_email}[^@]+@[^",]+?)\\?"""",
    """"result":"({outcome}[^"]+)""",
    """"Category":"({category}[^"]+)""",
    """"Severity":"({alert_severity}[^"]+)""",
    """"Source":"({additional_info}[^"]+)""",
    """"Status":"({status}[^"]+)""",
    """"category":"({alert_type}[^"]+)""",
    """"action":"({alert_name}[^"]+)""",
    """"src-account-name":"({account}[^"]+)""",
    """Workload":"({app}[^"]+)""",
    """"id":({alert_id}\d{1,100})"""
  ]
}
```