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
                """\s({host}\w+)\sSkyformation""",
                """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
                """destinationServiceName=({app}.+?)\s\w+="""
                """"+Action"+:"+({action}[^"]+)"+""",
                """"Username"+:"+({user_email}[^@]+@[^\.]+\.[^"]+)"""
		""""+Data"+:"+({additional_info}[^"]+)"""  
  ]
}
```