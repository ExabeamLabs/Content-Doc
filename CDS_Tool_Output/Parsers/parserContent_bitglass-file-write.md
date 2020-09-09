#### Parser Content
```Java
{
Name = bitglass-file-write
  Vendor = BitGlass
  Lms = Direct
  DataType = "file-write"
  IsHVF = true
  TimeFormat = "dd MMM yyyy HH:mm:ss"
  Conditions = [ """, Uploaded""", """ api.bitglass.com """ ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """"time":\s*"({time}\d+ \w+ \d\d\d\d \d\d:\d\d:\d\d)""",
    """"instancename":\s*"({host}[^"]+)"""",
    """"user":\s*"({user}[^"]+)"""",
    """"email":\s*"({user_email}[^"]+)"""",
    """"device":\s*"({os}[^"]+)"""",
    """"application":\s*"({app}[^"]+)"""",
    """"ipaddress":\s*"({src_ip}[a-fA-F\d.:]+)"""",
    """"activity":\s*"({accesses}[^"]+)",""",
    """"filename":\s*"({file_name}[^"]+?(\.({file_ext}[^."]+))?)",""",
    """"useragent":\s*"({user_agent}.+?)",""",
    """"url":\s*"({file_uri}.+?)",""",
    """"useragent":\s*".+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)"""
  ]
}
```