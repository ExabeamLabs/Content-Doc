#### Parser Content
```Java
{
Name = sophos-proxy-2
  Vendor = Sophos
  Product = Sophos UTM
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy:MM:dd-HH:mm:ss"
  Conditions = [ """ name="web request blocked""", """ fullreqtime="""" ]
  Fields = [
	"""({time}\d\d\d\d:\d\d:\d\d-\d\d:\d\d:\d\d)\s{1,100}({host}[\w\-.]+)""",
    """sub="(|({protocol}[^"]+))"""",
    """action="(|({action}[^"]+))"""",
    """method="(|({method}[^"]+))"""",
    """srcip="(|({src_ip}[^"]+))"""",
    """dstip="(|({dest_ip}[^"]+))"""",
    """user="(|({user}[^"]+))"""",
    """statuscode="(|({result_code}[^"]+))"""",
    """url="({full_url}[^"]+)""",
    """url="(?:-|({protocol}[^:]+))""",
    """url="(?:-|\w+:\/+[^\/]+)({uri_path}\/[^?\s"]+)""",
    """url="(?:-|(?=(?)(?:[^?]+({uri_query}\?[^\s"]+))))""",
    """url="(?:[^:]+:\/+)({web_domain}[^\/:\s]+)""",
    """url="(.*?)({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^\.\s\/:]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+(\s|\/|$))[^\s\/]+)""",
    """referer="(|({referrer}[^"]+))"""",
    """ua="(|({user_agent}[^"]+))"""",
    """ua="(?:-|Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
    """category="({category}[^"]+)""",
  ]
}
```