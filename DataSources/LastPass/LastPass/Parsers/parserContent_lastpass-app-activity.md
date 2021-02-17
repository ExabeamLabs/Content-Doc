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
                """"+Action"+:"+({action}[^"]+)"+""",
                """msg=({additional_info}.+?)\s\w+="""
                """fileType=({file_type}[^\s]+)""",
                """"Username"+:"+API:\s*({user}[^"]+)"""
                """flexString1=({activity}[^\s]+)"""
      ]
}
```