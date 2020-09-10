#### Parser Content
```Java
{
Name = cloudflare-app-activity
  Vendor = Cloudflare
  Product = Cloudflare
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