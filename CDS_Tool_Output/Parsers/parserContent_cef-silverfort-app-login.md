#### Parser Content
```Java
{
Name = cef-silverfort-app-login
  Vendor = Silverfort
  Product = Silverfort
  Lms = Direct
  DataType = "app-login"
  TimeFormat ="dd/MM/yyyy HH:mm:ss.SSS"
  Conditions = [ """ CEF:""", """|Silverfort|Admin Console|""", """|Authentication|Authentication request|""" ]
  Fields = [
    """\s+({host}[\w\-.]+)\s+CEF:""",
    """rt=({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d.\d\d\d)""",
    """suser=(({user_email}[^@]+@[^\s]+)|({user}.+?))\ssntdom=""",
    """sntdom=({domain}[^\s]+)""",
    """shost=(n\/a|({src_host}[^\s]+))""",
    """src=(n\/a|({src_ip}[a-fA-F\d\.:]+))""",
    """dhost=(n\/a|({dest_host}[^\s]+))""",
    """app=(n\/a|({app}[^\s]+))""",
    """cs2=({outcome}[^\s]+)""",
  ]
}
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