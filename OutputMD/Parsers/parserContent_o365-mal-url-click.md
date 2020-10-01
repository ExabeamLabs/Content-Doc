#### Parser Content
```Java
{
Name = o365-mal-url-click
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"Workload""", """"ResultStatus""", """"Operation""", """MaliciousUrlClick""", """AlertEntityGenerated""", """dproc=management-general""" ]
  Fields = [
    """"CreationTime\\*"+:[\s\\]*"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]+)""",
    """"Operation\\*"+:[\s\\]*"+({activity}[^"\\\.]*)""",
    """requestClientApplication=({app}.+?)\s+(\w+=|$)""",
    """"AlertEntityId[\\"]+:[\\"]+({malware_url}[^"]+)""" 
    """"ResultStatus[\\"]+:[\\"]+({outcome}[^"\\\}\{,:]+)""" 
    """"Category[\\"]+:[\\"]+({category}[^"\\\}\{,:]+)""" 
    """"AlertType[\\"]+:[\\"]+({alert_type}[^"\\\}\{,:]+)"""
    """"Severity[\\"]+:[\\"]+({alert_severity}[^"\\\}\{,:]+)""" 
    """"Name[\\"]+:[\\"]+({alert_name}[^"\\\}\{,:]+)"""
    """"trc[\\"]+:[\\"]+({user_email}[^"\s@]+@[^"\s@\\]+)""",

  ]
}
```