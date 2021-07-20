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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"when":"({time}[^"]{1,2000})"""",
    """suser=({user}[^\s]{1,2000})""",
    """destinationServicename=({app}[^\s]{1,2000})""",
    """flexString1=({activity}[^\s]{1,2000})""",
    """src=({src_ip}\d{1,100}.\d{1,100}.\d{1,100}.\d{1,100})""",
    """msg=({additional_info}.+?)\s\w+=""",
  ]
}
```