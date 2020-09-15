#### Parser Content
```Java
{
Name = bitglass-app-login
  Vendor = Bitglass
  Product = Bitglass
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "dd MMM yyyy HH:mm:ss"
  Conditions = [ """"activity":""", """"Login"""", """api.bitglass.com""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """"time":\s*"({time}\d+ \w+ \d\d\d\d \d\d:\d\d:\d\d)""",
    """"instancename":\s*"({host}[^"]+)"""",
    """"user":\s*"({user}[^"\s@]+)"""",
    """"user":\s*"({user_fullname}[^"\s@]+\s+[^"\s@]+)"""",
    """"email":\s*"({user_email}[^@]+@({email_domain}[^"]+))"""",
    """"device":\s*"({os}[^"]+)"""",
    """"application":\s*"({app}[^"]+)"""",
    """"ipaddress":\s*"({src_ip}[a-fA-F\d.:]+)"""",
    """"useragent":\s*"({user_agent}.+?)",""",
    """"useragent":\s*".+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""""
  ]
}
```