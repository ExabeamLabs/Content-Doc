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
      """ClientUserName:\s{0,100}"(?:anonymous|({user}[^"]+))"""",
      """ClientAgent:\s{0,100}"({user_agent}[^"]+)"""",
      """logTime:\s{0,100}"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """servername:\s{0,100}"({host}[^"]+)"""",
      """bytesrecvd:\s{0,100}"({bytes_in}\d{1,100})""",
      """bytessent:\s{0,100}"({bytes_out}\d{1,100})""",
      """transport:\s{0,100}"({protocol}[^"]+)"""",
      """Action:\s{0,100}"({action}[^"]+)"""",
      """DecryptedIP:\s{0,100}"({src_ip}[^"]+)"""",
      """UrlDestHost:\s{0,100}"({web_domain}[^"]+)"""",
      """DestHostPort:\s{0,100}"({dest_port}[^"]+)"""",
      """mimetype:\s{0,100}"(?:-|({mime}[^"]+))"""",
      """operation:\s{0,100}"(?:-|({method}[^"]+))"""",
      """uri:\s{0,100}"(?:-|((\w+:\/+)?[^\/]+\/({uri_path}.+?)))(\?|")""",
      """uri:\s{0,100}"(?:-|((\w+:\/+)?[^?]+({uri_query}\?.+?)))"""",
      """UrlDestHost:\s{0,100}"([^"]*?)({top_domain}[^.\s\/:,"]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+).+?)""""
      """ClientAgent:\s{0,100}"(?:-|({browser}[\w\-]+))""",
      """ClientAgent:\s{0,100}"(?:-|({browser}[\w\-]+)\/[\d\._]+)""",
      """ClientAgent:\s{0,100}"(?:-|({browser}[^\/]+)[^"]+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
      """ClientAgent:\s{0,100}"(?:-|Mozilla\/[^"]+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
      """ClientAgent:\s{0,100}"(?:-|Mozilla\/[^"]+\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]+Gecko\/\d{1,100}\s{1,100}({browser}\w+))"""
    ]
  }
```