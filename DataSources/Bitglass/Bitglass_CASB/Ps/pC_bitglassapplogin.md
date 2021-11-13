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
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"time":\s{0,100}"({time}\d{1,100} \w+ \d\d\d\d \d\d:\d\d:\d\d)""",
    """"instancename":\s{0,100}"({host}[^"]{1,2000})"""",
    """"user":\s{0,100}"({user}[^"\s@]{1,2000})"""",
    """"user":\s{0,100}"({user_fullname}[^"\s@]{1,2000}\s{1,100}[^"\s@]{1,2000})"""",
    """"email":\s{0,100}"({user_email}[^@]{1,2000}@({email_domain}[^"]{1,2000}))"""",
    """"application":\s{0,100}"({app}[^"]{1,2000})"""",
    """"ipaddress":\s{0,100}"({src_ip}[a-fA-F\d.:]{1,2000})"""",
    """"useragent":\s{0,100}"({user_agent}.+?)",""",
  ]


}
```