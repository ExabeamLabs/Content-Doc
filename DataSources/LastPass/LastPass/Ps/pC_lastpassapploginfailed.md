#### Parser Content
```Java
{
Name = lastpass-app-login-failed
  Vendor = LastPass
  Product = LastPass
  Lms = Splunk
  DataType = "failed-app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """"Data":""", """Action":"Failed Login Attempt""","""dproc=EventReporting""","""destinationServiceName =LastPass"""]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"Time":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """"IP_Address":"({src_ip}[a-fA-F\d:.]{1,2000})"""",
    """destinationServiceName =({app}[^=]{1,2000}?)\s\w{1,2000}=""",
    """"{1,20}Action"{1,20}:"{1,20}({event_name}[^"]{1,2000})"{1,20}""",
    """"Username"{1,20}:"{1,20}({user_email}[^@"]{1,2000}@[^\."]{1,2000}\.[^"]{1,2000})""",
    """"{1,20}Data"{1,20}:"{1,20}({additional_info}[^"\}]{1,2000})"""
  ]


}
```