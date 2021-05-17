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
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"time":\s{0,100}"({time}\d{1,100} \w+ \d\d\d\d \d\d:\d\d:\d\d)""",
    """"instancename":\s{0,100}"({host}[^"]{1,2000})"""",
    """"user":\s{0,100}"({user}[^"]{1,2000})"""",
    """"email":\s{0,100}"({email_user}[^"]{1,2000})"""",
    """"device":\s{0,100}"({os}[^"]{1,2000})"""",
    """"application":\s{0,100}"({app}[^"]{1,2000})"""",
    """"ipaddress":\s{0,100}"({src_ip}[a-fA-F\d.:]{1,2000})"""",
    """"filename":\s{0,100}"({file_name}[^"]{1,2000}(\.({file_ext}[^."]{1,2000}))?)",""",
    """"useragent":\s{0,100}"({user_agent}.+?)",""",
    """"emailfrom":\s{0,100}"({sender}[^"]{1,2000})"""",
    """"emailto":\s{0,100}"({recipients}[^"]{1,2000})"""",
    """"emailto":\s{0,100}"({recipient}[^",]{1,2000})""",
    """"emailto":\s{0,100}"({external_address}[^",@]{1,2000}@({external_domain}[^",]{1,2000}))""",
    """"emailsubject":\s{0,100}"({subject}[^"]{1,2000})""""
  ]
}
```