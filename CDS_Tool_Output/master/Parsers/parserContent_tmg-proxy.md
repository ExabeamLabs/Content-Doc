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
      """ClientUserName:\s*"(?:anonymous|({user}[^"]+))"""",
      """ClientAgent:\s*"({user_agent}[^"]+)"""",
      """logTime:\s*"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """servername:\s*"({host}[^"]+)"""",
      """bytesrecvd:\s*"({bytes_in}\d+)""",
      """bytessent:\s*"({bytes_out}\d+)""",
      """transport:\s*"({protocol}[^"]+)"""",
      """Action:\s*"({action}[^"]+)"""",
      """DecryptedIP:\s*"({src_ip}[^"]+)"""",
      """UrlDestHost:\s*"({web_domain}[^"]+)"""",
      """DestHostPort:\s*"({dest_port}[^"]+)"""",
      """mimetype:\s*"(?:-|({mime}[^"]+))"""",
      """operation:\s*"(?:-|({method}[^"]+))"""",
      """uri:\s*"(?:-|((\w+:\/+)?[^\/]+\/({uri_path}.+?)))(\?|")""",
      """uri:\s*"(?:-|((\w+:\/+)?[^?]+({uri_query}\?.+?)))"""",
      """UrlDestHost:\s*"([^"]*?)({top_domain}[^.\s\/:,"]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+).+?)""""
      """ClientAgent:\s*"(?:-|({browser}[\w\-]+))""",
      """ClientAgent:\s*"(?:-|({browser}[\w\-]+)\/[\d\._]+)""",
      """ClientAgent:\s*"(?:-|({browser}[^\/]+)[^"]+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
      """ClientAgent:\s*"(?:-|Mozilla\/[^"]+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
      """ClientAgent:\s*"(?:-|Mozilla\/[^"]+\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]+Gecko\/\d+\s+({browser}\w+))"""
    ]
  }
```