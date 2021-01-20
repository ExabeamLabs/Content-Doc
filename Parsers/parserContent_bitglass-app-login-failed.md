#### Parser Content
```Java
{
Name = bitglass-app-login-failed
  Vendor = BitGlass
  Product = BitGlass
  Lms = Direct
  DataType = "failed-app-login"
  TimeFormat = "dd MMM yyyy HH:mm:ss"
  Conditions = [ """"activity":""", """"Failure, Login"""", """api.bitglass.com""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """"time":\s*"({time}\d+ \w+ \d\d\d\d \d\d:\d\d:\d\d)""",
    """"instancename":\s*"({host}[^"]+)"""",
    """"user":\s*"({user}[^"\s@]+)"""",
    """"user":\s*"({user_fullname}[^"\s@]+\s+[^"\s@]+)"""",
    """"email":\s*"({user_email}[^"]+)"""",
    """"device":\s*"({os}[^"]+)"""",
    """"application":\s*"({app}[^"]+)"""",
    """"ipaddress":\s*"({src_ip}[a-fA-F\d.:]+)"""",
    """"useragent":\s*"({user_agent}.+?)",""",
    """"useragent":\s*".+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)"""",
    """"details":\s*"({failure_reason}.+?)","""
  ]
}
```