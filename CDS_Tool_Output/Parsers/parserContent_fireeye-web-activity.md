#### Parser Content
```Java
{
Name = fireeye-web-activity
  Vendor = FireEye
  Product = FireEye Network Security (NX)
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"uri_parsed":""", """"useragent":""", """"dstdomain":""" ]
  Fields = [
    """"eventtime":\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"uri_parsed":\s*"({uri_path}[^"]+)""",
    """"srcipv4":\s*"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """"rcvdbodybytes":\s*({bytes_in}\d+)""",
    """"sentbodybytes":\s*({bytes_out}\d+)""",
    """"field":\s*"httpmethod/method"[^\}]*?"value":\s*"({method}[^"]+)""",
    """""value":\s*"({method}[^"]+)"[^\}]*?"field":\s*"httpmethod/method"""",
    """"dstipv4":\s*"({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """"statuscode":\s*({result_code}\d+)""",
    """"dstport":\s*({dest_port}\d+)""",
    """"srcport":\s*({src_port}\d+)""",
    """"rawmsghostname":\s*"({host}[^"]+)""",
    """"dstdomain":\s*"({web_domain}[^"]+)""",
    """"dstdomain":\s*"[^"]*?({top_domain}(?!(?:\d+\.){3}\d+)[^\."]+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)"""",
    """"useragent":\s*"({user_agent}[^"]+)""",
    """"useragent":\s*"[^"]*?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
    """"useragent":\s*"[^"]*?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
  ]
}
```