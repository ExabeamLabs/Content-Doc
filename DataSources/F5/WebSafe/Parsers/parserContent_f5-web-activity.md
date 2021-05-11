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
    """({host}[\w\-.]+)\s\S+\s({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d [-+]\d{1,100})\s{1,100}({src_ip}[A-Fa-f:\d.]+)\s(-|({user}[^\s\-]+))\s({dest_ip}[A-Fa-f:\d.]+)\s{1,100}.+?({result_code}\d{1,100})\s\d{1,100}\s\d{1,100}\s\S+\s"({user_agent}[^"]+)""",
    """"(?:-|Mozilla\/.+?\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(X|x)11|(W|w)indows|(L|l)inux|(M|m)acintosh|(D|d)arwin).+?({browser}Chrome|Safari|Opera|(F|f)irefox|MSIE|Trident))""",
    """cookiemonster=.+?(\}|\=\=)\s{1,100}({full_url}.+?)\s{0,100}$""",
    """cookiemonster=.+?(\}|\=\=)\s{1,100}(?:-|({protocol}[^:]+))""",
    """cookiemonster=.+?(\}|\=\=)\s{1,100}(?:[^:]+:\/+)({web_domain}[^\/:\s]+)""",
    """cookiemonster=.+?(\}|\=\=)\s{1,100}(?:-|\w+:\/+[^\/]+)({uri_path}\/[^?\s]+)""",
    """cookiemonster=.+?(\}|\=\=)\s{1,100}(?:-|(?=(?)(?:[^?]+({uri_query}\?[^\s"]+))))""",
    """cookiemonster=.+?(\}|\=\=)\s{1,100}(.*?)({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^\.\s\/:]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|afg))+(\s|\/|$))[^\s\/]+)""",
    """cookiemonster=.+?(\}|\=\=)\s{1,100}.+?METHOD=({method}\w+)""",
  ]
}
```