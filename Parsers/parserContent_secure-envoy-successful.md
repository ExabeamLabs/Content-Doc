#### Parser Content
```Java
{
Name = secure-envoy-successful
  Vendor = Secure Envoy
  Product = Secure Envoy
  Lms = Direct
  DataType = ""authentication-successful""
  TimeFormat = "dd MM yyyy HH:mm:ss"
  Conditions = ["""TORVMVERIFY""","""Passcode OK"""]
  Fields = [
    """({time}\d+\s\w+\s\d+\s\d+:\d+:\d+)\s*""",
    """TORVMVERIFY01\s({server_name}[^\s]+)\sUserID=(({user}[^\s@]+?)@({domain}[^\s]+)|({=user}[^\s]+))\s({auth_method}Passcode OK)""",
    """ClientIP=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """RemoteID=({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
	
  ]
}

{
  Name = cloudflare-app-activity
  Vendor = Cloudflare
  Product = Cloudflare Insights
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """CEF:""", """destinationServiceName=cloudflare""", """"when":"""" ]
  Fields = [
    """"when":"({time}[^"]+)"""",
    """suser=({user}[^\s]+)""",
    """destinationServicename=({app}[^\s]+)""",
    """flexString1=({activity}[^\s]+)""",
    """src=({src_ip}\d+.\d+.\d+.\d+)""",
    """msg=({additional_info}.+?)\s\w+=""",
  ]
}
```