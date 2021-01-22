#### Parser Content
```Java
{
Name = s-sharepoint-proxy
  Vendor = Microsoft
  Product = Sharepoint
  Lms = Splunk
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """<custom condition>""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d) ({src_ip}[a-fA-F\d.:]+) GET""",
    """GET \S+ \S+ ({dest_port}\d+) (-|[^|]+\|(({domain}[^\\]+)\\)?({user}[^\\\s]+)) ({dest_ip}[a-fA-F\d.:]+)""",
    """GET (\S+ ){5}\S*({os}iOS|Android|BlackBerry|Windows Phone|BeOS|Windows|Linux|Macintosh|Darwin)""",
    """GET (\S+ ){5}\S*({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """GET (\S+ ){6}(-|({full_url}\S+))""",
    """GET (\S+ ){6}\w+:\/+({web_domain}[^/]+)""",
    """GET (\S+ ){6}\w+:\/+[^/]*?({top_domain}[^./]+(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)\/""",
    """GET (\S+ ){7}({result_code}\d+)""",
  ]
}
```