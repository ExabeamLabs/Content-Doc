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
    """"CreationTime\\*"{1,20}:[\s\\]{0,2000}"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"Operation\\*"{1,20}:[\s\\]{0,2000}"{1,20}({activity}[^"\\\.]{0,2000})""",
    """requestClientApplication=({app}.+?)\s{1,100}(\w+=|$)""",
    """"AlertEntityId[\\"]{1,2000}:[\\"]{1,2000}({malware_url}[^"]{1,2000})""" 
    """"ResultStatus[\\"]{1,2000}:[\\"]{1,2000}({outcome}[^"\\\}\{,:]{1,2000})""" 
    """"Category[\\"]{1,2000}:[\\"]{1,2000}({category}[^"\\\}\{,:]{1,2000})""" 
    """"AlertType[\\"]{1,2000}:[\\"]{1,2000}({alert_type}[^"\\\}\{,:]{1,2000})"""
    """"Severity[\\"]{1,2000}:[\\"]{1,2000}({alert_severity}[^"\\\}\{,:]{1,2000})""" 
    """"Name[\\"]{1,2000}:[\\"]{1,2000}({alert_name}[^"\\\}\{,:]{1,2000})"""
    """"trc[\\"]{1,2000}:[\\"]{1,2000}({user_email}[^"\s@]{1,2000}@[^"\s@\\]{1,2000})""",

  ]


}
```