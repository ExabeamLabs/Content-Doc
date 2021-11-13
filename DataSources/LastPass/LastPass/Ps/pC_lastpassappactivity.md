#### Parser Content
```Java
{
Name = lastpass-app-activity
  Vendor = LastPass
  Product = LastPass
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """Action":""","""dproc=EventReporting""","""destinationServiceName =LastPass"""]
  Fields = [
                """exabeam_host=({host}[\w.\-]{1,2000})""",
                """\s({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"""
                """"IP_Address":"({src_ip}[a-fA-F\d:.]{1,2000})"""",
                """destinationServiceName =({app}.+?)\s\w+=""",
                """"{1,20}Action"{1,20}:"{1,20}({event_name}[^"]{1,2000})"{1,20}""",
                """msg=({additional_info}.+?)\s\w+="""
                """fileType=({file_type}[^\s]{1,2000})""",
                """"Username"{1,20}:"{1,20}({user_email}[^@"]{1,2000}@[^\.]{1,2000}\.[^"]{1,2000})""",
                """"Username"{1,20}:"{1,20}API:\s{0,100}({user}[^"]{1,2000})"""
      ]
      DupFields = [ "event_name->activity" ]


}
```