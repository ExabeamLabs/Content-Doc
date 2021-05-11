#### Parser Content
```Java
{
Name = cloudflare-app-activity
  Vendor = Cloudflare
  Product = Cloudflare Insights
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """CEF:""", """destinationServiceName=cloudflare""", """"when":"""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"when":"({time}[^"]+)"""",
    """suser=({user}[^\s]+)""",
    """destinationServicename=({app}[^\s]+)""",
    """flexString1=({activity}[^\s]+)""",
    """src=({src_ip}\d{1,100}.\d{1,100}.\d{1,100}.\d{1,100})""",
    """msg=({additional_info}.+?)\s\w+=""",
  ]
}
```