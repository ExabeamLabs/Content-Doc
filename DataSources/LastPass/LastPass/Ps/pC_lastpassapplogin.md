#### Parser Content
```Java
{
Name = lastpass-app-login
  Vendor = LastPass
  Product = LastPass
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """Skyformation""","""Action":"Log in""","""dproc=EventReporting"""]
  Fields = [
                """\s({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"""
                """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
                """destinationServiceName =({app}.+?)\s\w+="""
                """"{1,20}Action"{1,20}:"{1,20}({action}[^"]{1,2000})"{1,20}""",
                """"Username"{1,20}:"{1,20}({user_email}[^@]{1,2000}@[^\.]{1,2000}\.[^"]{1,2000})"""
		""""{1,20}Data"{1,20}:"{1,20}({additional_info}[^"]{1,2000})"""  
  ]


}
```