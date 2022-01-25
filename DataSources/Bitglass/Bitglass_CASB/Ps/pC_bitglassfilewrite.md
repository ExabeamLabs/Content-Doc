#### Parser Content
```Java
{
Name = bitglass-file-write
  Vendor = Bitglass
  Product = Bitglass CASB
  Lms = Direct
  DataType = "file-write"
  IsHVF = true
  TimeFormat = "dd MMM yyyy HH:mm:ss"
  Conditions = [ """, Uploaded""", """ api.bitglass.com """ ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"time":\s{0,100}"({time}\d{1,100} \w+ \d\d\d\d \d\d:\d\d:\d\d)""",
    """"instancename":\s{0,100}"({host}[^"]{1,2000})"""",
    """"user":\s{0,100}"({user}[^"]{1,2000})"""",
    """"email":\s{0,100}"({user_email}[^"]{1,2000})"""",
    """"device":\s{0,100}"({os}[^"]{1,2000})"""",
    """"application":\s{0,100}"({app}[^"]{1,2000})"""",
    """"ipaddress":\s{0,100}"({src_ip}[a-fA-F\d.:]{1,2000})"""",
    """"activity":\s{0,100}"({accesses}[^"]{1,2000})",""",
    """"filename":\s{0,100}"({file_name}[^"]{1,2000}?(\.({file_ext}[^."]{1,2000}))?)",""",
    """"useragent":\s{0,100}"({user_agent}.+?)",""",
    """"url":\s{0,100}"({file_uri}.+?)",""",
    """"useragent":\s{0,100}".+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)"""
  ]


}
```