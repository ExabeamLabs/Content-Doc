#### Parser Content
```Java
{
Name = bitglass-dlp-email-alert-out
  Vendor = Bitglass
  Product = Bitglass CASB
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "dd MMM yyyy HH:mm:ss"
  Conditions = [ """Email, Send, Web""", """ api.bitglass.com """ ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """"time":\s*"({time}\d+ \w+ \d\d\d\d \d\d:\d\d:\d\d)""",
    """"instancename":\s*"({host}[^"]+)"""",
    """"user":\s*"({user}[^"]+)"""",
    """"email":\s*"({email_user}[^"]+)"""",
    """"device":\s*"({os}[^"]+)"""",
    """"application":\s*"({app}[^"]+)"""",
    """"ipaddress":\s*"({src_ip}[a-fA-F\d.:]+)"""",
    """"filename":\s*"({file_name}[^"]+(\.({file_ext}[^."]+))?)",""",
    """"useragent":\s*"({user_agent}.+?)",""",
    """"emailfrom":\s*"({sender}[^"]+)"""",
    """"emailto":\s*"({recipients}[^"]+)"""",
    """"emailto":\s*"({recipient}[^",]+)""",
    """"emailto":\s*"({external_address}[^",@]+@({external_domain}[^",]+))""",
    """"emailsubject":\s*"({subject}[^"]+)""""
  ]
}
```