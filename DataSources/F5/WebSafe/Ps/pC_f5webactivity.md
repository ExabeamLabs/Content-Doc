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
    """"(?:-|Mozilla\/.+?\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(X|x)11|(W|w)indows|(L|l)inux|(M|m)acintosh|(D|d)arwin).+?({browser}Chrome|Safari|Opera|(F|f)irefox|MSIE|Trident))""",
    """cookiemonster=.+?(\}|\=\=)\s{1,100}({full_url}.+?)\s{0,100}$""",
    """cookiemonster=.+?(\}|\=\=)\s{1,100}(?:-|({protocol}[^:]{1,2000}))""",
    """cookiemonster=.+?(\}|\=\=)\s{1,100}(?:[^:]{1,2000}:\/+)({web_domain}[^\/:\s]{1,2000})""",
    """cookiemonster=.+?(\}|\=\=)\s{1,100}(?:-|\w+:\/+[^\/]{1,2000})({uri_path}\/[^?\s]{1,2000})""",
    """cookiemonster=.+?(\}|\=\=)\s{1,100}(?:-|(?=(?)(?:[^?]{1,2000}({uri_query}\?[^\s"]{1,2000}))))""",
    """cookiemonster=.+?(\}|\=\=)\s{1,100}(.*?)({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^\.\s\/:]{1,2000}(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|afg))+(\s|\/|$))[^\s\/]{1,2000})""",
    """cookiemonster=.+?(\}|\=\=)\s{1,100}.+?METHOD=({method}\w+)""",
  ]


}
```