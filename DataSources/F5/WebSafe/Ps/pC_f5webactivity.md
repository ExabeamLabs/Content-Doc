#### Parser Content
```Java
{
Name = f5-web-activity
  Vendor = F5
  Product = WebSafe
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "dd/MM/yyyy HH:mm:ss Z"
  Conditions = [ """cookiemonster=""" ]
  Fields = [
    """({host}[\w\-.]{1,2000})\s\S+\s({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d [-+]\d{1,100})\s{1,100}({src_ip}[A-Fa-f:\d.]{1,2000})\s(-|({user}[^\s\-]{1,2000}))\s({dest_ip}[A-Fa-f:\d.]{1,2000})\s{1,100}.+?({result_code}\d{1,100})\s\d{1,100}\s\d{1,100}\s\S+\s"({user_agent}[^"]{1,2000})""",
    """cookiemonster=.+?(\}|\=\=)\s{1,100}({full_url}.+?)\s{0,100}$""",
    """cookiemonster=.+?(\}|\=\=)\s{1,100}(?:-|({protocol}[^:]{1,2000}))""",
    """cookiemonster=.+?(\}|\=\=)\s{1,100}(?:[^:]{1,2000}:\/+)({web_domain}[^\/:\s]{1,2000})""",
    """cookiemonster=.+?(\}|\=\=)\s{1,100}(?:-|\w+:\/+[^\/]{1,2000})({uri_path}\/[^?\s]{1,2000})""",
    """cookiemonster=.+?(\}|\=\=)\s{1,100}(?:-|(?=(?)(?:[^?]{1,2000}({uri_query}\?[^\s"]{1,2000}))))""",
    """cookiemonster=.+?(\}|\=\=)\s{1,100}.+?METHOD=({method}\w+)""",
  ]


}
```