#### Parser Content
```Java
{
Name = f5-web-activity
  Vendor = F5 Networks
  Product = WebSafe
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "dd/MM/yyyy HH:mm:ss Z"
  Conditions = [ """cookiemonster=""" ]
  Fields = [
    """({host}[\w\-.]+)\s\S+\s({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d [-+]\d+)\s+({src_ip}[A-Fa-f:\d.]+)\s(-|({user}[^\s\-]+))\s({dest_ip}[A-Fa-f:\d.]+)\s+.+?({result_code}\d+)\s\d+\s\d+\s\S+\s"({user_agent}[^"]+)""",
    """"(?:-|Mozilla\/.+?\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(X|x)11|(W|w)indows|(L|l)inux|(M|m)acintosh|(D|d)arwin).+?({browser}Chrome|Safari|Opera|(F|f)irefox|MSIE|Trident))""",
    """cookiemonster=.+?(\}|\=\=)\s+({full_url}.+?)\s*$""",
    """cookiemonster=.+?(\}|\=\=)\s+(?:-|({protocol}[^:]+))""",
    """cookiemonster=.+?(\}|\=\=)\s+(?:[^:]+:\/+)({web_domain}[^\/:\s]+)""",
    """cookiemonster=.+?(\}|\=\=)\s+(?:-|\w+:\/+[^\/]+)({uri_path}\/[^?\s]+)""",
    """cookiemonster=.+?(\}|\=\=)\s+(?:-|(?=(?)(?:[^?]+({uri_query}\?[^\s"]+))))""",
    """cookiemonster=.+?(\}|\=\=)\s+(.*?)({top_domain}(?!(?:\d+\.){3}\d+)[^\.\s\/:]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|afg))+(\s|\/|$))[^\s\/]+)""",
    """cookiemonster=.+?(\}|\=\=)\s+.+?METHOD=({method}\w+)""",
  ]
}
```