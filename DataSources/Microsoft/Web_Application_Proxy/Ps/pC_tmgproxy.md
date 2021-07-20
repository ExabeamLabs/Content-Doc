#### Parser Content
```Java
{
Name = tmg-proxy
    Vendor = Microsoft
    Product = Web Application Proxy
    Lms = Direct
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """ UrlDestHost:""", """RawTable:""", """ uri:""" ]
    Fields = [
      """ClientUserName:\s{0,100}"(?:anonymous|({user}[^"]{1,2000}))"""",
      """ClientAgent:\s{0,100}"({user_agent}[^"]{1,2000})"""",
      """logTime:\s{0,100}"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """servername:\s{0,100}"({host}[^"]{1,2000})"""",
      """bytesrecvd:\s{0,100}"({bytes_in}\d{1,100})""",
      """bytessent:\s{0,100}"({bytes_out}\d{1,100})""",
      """transport:\s{0,100}"({protocol}[^"]{1,2000})"""",
      """Action:\s{0,100}"({action}[^"]{1,2000})"""",
      """DecryptedIP:\s{0,100}"({src_ip}[^"]{1,2000})"""",
      """UrlDestHost:\s{0,100}"({web_domain}[^"]{1,2000})"""",
      """DestHostPort:\s{0,100}"({dest_port}[^"]{1,2000})"""",
      """mimetype:\s{0,100}"(?:-|({mime}[^"]{1,2000}))"""",
      """operation:\s{0,100}"(?:-|({method}[^"]{1,2000}))"""",
      """uri:\s{0,100}"(?:-|((\w+:\/+)?[^\/]{1,2000}\/({uri_path}.+?)))(\?|")""",
      """uri:\s{0,100}"(?:-|((\w+:\/+)?[^?]{1,2000}({uri_query}\?.+?)))"""",
      """UrlDestHost:\s{0,100}"([^"]{0,2000}?)({top_domain}[^.\s\/:,"]{1,2000}(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+).+?)""""
      """ClientAgent:\s{0,100}"(?:-|({browser}[\w\-]{1,2000}))""",
      """ClientAgent:\s{0,100}"(?:-|({browser}[\w\-]{1,2000})\/[\d\._]{1,2000})""",
      """ClientAgent:\s{0,100}"(?:-|({browser}[^\/]{1,2000})[^"]{1,2000}({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
      """ClientAgent:\s{0,100}"(?:-|Mozilla\/[^"]{1,2000}\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]{1,2000}?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
      """ClientAgent:\s{0,100}"(?:-|Mozilla\/[^"]{1,2000}\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]{1,2000}Gecko\/\d{1,100}\s{1,100}({browser}\w+))"""
    ]
  }
```