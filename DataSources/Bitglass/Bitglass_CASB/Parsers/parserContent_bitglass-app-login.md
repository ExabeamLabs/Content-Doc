#### Parser Content
```Java
{
Name = bitglass-app-login
  Vendor = Bitglass
  Product = Bitglass CASB
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "dd MMM yyyy HH:mm:ss"
  Conditions = [ """"activity":""", """"Login"""", """api.bitglass.com""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """"time":\s{0,100}"({time}\d{1,100} \w+ \d\d\d\d \d\d:\d\d:\d\d)""",
    """"instancename":\s{0,100}"({host}[^"]+)"""",
    """"user":\s{0,100}"({user}[^"\s@]+)"""",
    """"user":\s{0,100}"({user_fullname}[^"\s@]+\s{1,100}[^"\s@]+)"""",
    """"email":\s{0,100}"({user_email}[^@]+@({email_domain}[^"]+))"""",
    """"device":\s{0,100}"({os}[^"]+)"""",
    """"application":\s{0,100}"({app}[^"]+)"""",
    """"ipaddress":\s{0,100}"({src_ip}[a-fA-F\d.:]+)"""",
    """"useragent":\s{0,100}"({user_agent}.+?)",""",
    """"useragent":\s{0,100}".+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""""
  ]
}
```