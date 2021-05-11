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
    """"time":\s{0,100}"({time}\d{1,100} \w+ \d\d\d\d \d\d:\d\d:\d\d)""",
    """"instancename":\s{0,100}"({host}[^"]+)"""",
    """"user":\s{0,100}"({user}[^"]+)"""",
    """"email":\s{0,100}"({email_user}[^"]+)"""",
    """"device":\s{0,100}"({os}[^"]+)"""",
    """"application":\s{0,100}"({app}[^"]+)"""",
    """"ipaddress":\s{0,100}"({src_ip}[a-fA-F\d.:]+)"""",
    """"filename":\s{0,100}"({file_name}[^"]+(\.({file_ext}[^."]+))?)",""",
    """"useragent":\s{0,100}"({user_agent}.+?)",""",
    """"emailfrom":\s{0,100}"({sender}[^"]+)"""",
    """"emailto":\s{0,100}"({recipients}[^"]+)"""",
    """"emailto":\s{0,100}"({recipient}[^",]+)""",
    """"emailto":\s{0,100}"({external_address}[^",@]+@({external_domain}[^",]+))""",
    """"emailsubject":\s{0,100}"({subject}[^"]+)""""
  ]
}
```