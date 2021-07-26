#### Parser Content
```Java
{
Name = lastpass-app-activity
  Vendor = LastPass
  Product = LastPass
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """Skyformation""","""Action":""","""dproc=EventReporting"""]
  Fields = [
                """\s({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"""
                """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
                """destinationServiceName=({app}.+?)\s\w+=""",
                """"{1,20}Action"{1,20}:"{1,20}({action}[^"]{1,2000})"{1,20}""",
                """msg=({additional_info}.+?)\s\w+="""
                """fileType=({file_type}[^\s]{1,2000})""",
                """"Username"{1,20}:"{1,20}API:\s{0,100}({user}[^"]{1,2000})"""
                """flexString1=({activity}[^\s]{1,2000})"""
      ]
}
```