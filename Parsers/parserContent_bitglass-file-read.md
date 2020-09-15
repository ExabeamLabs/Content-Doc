#### Parser Content
```Java
{
Name = bitglass-file-read
  Vendor = Bitglass
  Product = Bitglass
  Lms = Direct
  DataType = "file-read"
  IsHVF = true
  TimeFormat = "dd MMM yyyy HH:mm:ss"
  Conditions = [ """"activity":""", """, Downloaded""", """ api.bitglass.com """ ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """"time":\s*"({time}\d+ \w+ \d\d\d\d \d\d:\d\d:\d\d)""",
    """"instancename":\s*"({host}[^"]+)"""",
    """"user":\s*"({user}[^"]+)"""",
    """"email":\s*"({user_email}[^"]+)"""",
    """"device":\s*"({os}[^"]+)"""",
    """"application":\s*"({app}[^"]+)"""",
    """"ipaddress":\s*"({src_ip}[a-fA-F\d.:]+)"""",
    """"filename":\s*"({file_name}[^"]+?(\.({file_ext}[^."]+))?)",""",
    """"activity":\s*"({accesses}[^"]+)",""",
    """"useragent":\s*"({user_agent}.+?)",""",
    """"url":\s*"({file_uri}.+?)",""",
    """"useragent":\s*".+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)"""
  ]
}
```