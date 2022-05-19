#### Parser Content
```Java
{
Name = lastpass-app-activity
  Vendor = LastPass
  Product = LastPass
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Action":""","""dproc=EventReporting""","""destinationServiceName =LastPass"""]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"Time":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """"IP_Address":"({src_ip}[a-fA-F\d:.]{1,2000})"""",
    """destinationServiceName =({app}[^=]{1,2000}?)\s\w{1,2000}=""",
    """"{1,20}Action"{1,20}:"{1,20}({event_name}[^"]{1,2000})"{1,20}""",
    """"Username"{1,20}:"{1,20}({user_email}[^@"]{1,2000}@[^\."]{1,2000}\.[^"]{1,2000})""",
    """"Username"{1,20}:"{1,20}API:\s{0,100}({user}[^"]{1,2000})""",
    """"{1,20}Action"{1,20}:"{1,20}({action}[^"]{1,2000})"{1,20}""",
    """"{1,20}Data"{1,20}:"{1,20}({additional_info}[^"\}]{1,2000})"""
  ]
  DupFields = [ "event_name->activity" ]


}
```