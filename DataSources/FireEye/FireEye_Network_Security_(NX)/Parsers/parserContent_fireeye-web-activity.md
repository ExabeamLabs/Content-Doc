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
    """"eventtime":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"uri_parsed":\s{0,100}"({uri_path}[^"]+)""",
    """"srcipv4":\s{0,100}"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """"rcvdbodybytes":\s{0,100}({bytes_in}\d{1,100})""",
    """"sentbodybytes":\s{0,100}({bytes_out}\d{1,100})""",
    """"field":\s{0,100}"httpmethod/method"[^\}]*?"value":\s{0,100}"({method}[^"]+)""",
    """""value":\s{0,100}"({method}[^"]+)"[^\}]*?"field":\s{0,100}"httpmethod/method"""",
    """"dstipv4":\s{0,100}"({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """"statuscode":\s{0,100}({result_code}\d{1,100})""",
    """"dstport":\s{0,100}({dest_port}\d{1,100})""",
    """"srcport":\s{0,100}({src_port}\d{1,100})""",
    """"rawmsghostname":\s{0,100}"({host}[^"]+)""",
    """"dstdomain":\s{0,100}"({web_domain}[^"]+)""",
    """"dstdomain":\s{0,100}"[^"]*?({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^\."]+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)"""",
    """"useragent":\s{0,100}"({user_agent}[^"]+)""",
    """"useragent":\s{0,100}"[^"]*?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
    """"useragent":\s{0,100}"[^"]*?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
  ]
}
```