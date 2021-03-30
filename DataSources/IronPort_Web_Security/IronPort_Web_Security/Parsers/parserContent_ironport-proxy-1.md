#### Parser Content
```Java
{
Name = ironport-proxy-1
  Product = IronPort Web Security
  TimeFormat = "dd/MM/yyyy:HH:mm:ss Z"
  Conditions = [ """IronPort-Web:""", """ TCP_""" ]
  Fields = ${IronPortParserTemplates.ironport-proxy.Fields} [
    """IronPort-Web:.+?({time}\d\d\/\w+\/\d\d\d\d:\d\d:\d\d:\d\d [-+]\d+)"\s\d+\s"({user_agent}[^"]+)""",
    """"IronPort-Web:.+"[^"]*({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]*"\s+$""",
    """"IronPort-Web:.+"[^"]*({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)[^"]*"\s+$""",
  ]
}
ironport-proxy = {
  Vendor = Cisco
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  Fields = [
    """(IronPort-Web|LogRythm):.+?({top_domain}[^\/\.\s]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)""",
    """(IronPort-Web|LogRythm):.+?({time}\d+).+?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s({proxy_action}[^\/]+)\/({result_code}\d+)\s\d+\s({method}\S+)\s(-|(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:({dest_port}\d+))?)|({full_url}(({protocol}[^:\\\/\s,"]+):[\\\/]+)?({web_domain}[^\\\/\s:,"]+)(:\d+)?({uri_path}\/[^\s\?",]*)?({uri_query}\?[^"\s]*)?))\s(-|"*(\w+\\({user}[^@\\\s",]+)[^\s"]*"*))\s(\w+\/)?(-|({=web_domain}\S+))\s(-|({mime}[^\s]+))\s.+?<(-|({category}[^,>]+))"""
  ]

```