#### Parser Content
```Java
{
Name = bitglass-file-read
  Vendor = Bitglass
  Product = Bitglass CASB
  Lms = Direct
  DataType = "file-read"
  IsHVF = true
  TimeFormat = "dd MMM yyyy HH:mm:ss"
  Conditions = [ """"activity":""", """, Downloaded""", """ api.bitglass.com """ ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """"time":\s{0,100}"({time}\d{1,100} \w+ \d\d\d\d \d\d:\d\d:\d\d)""",
    """"instancename":\s{0,100}"({host}[^"]+)"""",
    """"user":\s{0,100}"({user}[^"]+)"""",
    """"email":\s{0,100}"({user_email}[^"]+)"""",
    """"device":\s{0,100}"({os}[^"]+)"""",
    """"application":\s{0,100}"({app}[^"]+)"""",
    """"ipaddress":\s{0,100}"({src_ip}[a-fA-F\d.:]+)"""",
    """"filename":\s{0,100}"({file_name}[^"]+?(\.({file_ext}[^."]+))?)",""",
    """"activity":\s{0,100}"({accesses}[^"]+)",""",
    """"useragent":\s{0,100}"({user_agent}.+?)",""",
    """"url":\s{0,100}"({file_uri}.+?)",""",
    """"useragent":\s{0,100}".+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)"""
  ]
}
```