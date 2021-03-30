#### Parser Content
```Java
{
Name = s-apache-web-activity
  Vendor = Apache
  Product = Apache
  Lms = Splunk
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "dd/MMM/yyyy:HH:mm:ss Z"
  Conditions = [ """<cont-3878_condition>""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) \S+ ({user}[^\s]+) \[({time}\d\d\/\w+\/\d\d\d\d:\d\d:\d\d:\d\d [+-]\d+)\] "({method}\S+) [^"]*" ({result_code}\d+) \S+ "(-|({full_url}({protocol}[^:\\\/]+):[\\\/]+({web_domain}[^\\\/:]+)({uri_path}\/[^\s\?"]*)?({uri_query}\?[^"]+)?))" "({user_agent}[^"]+)" ({=web_domain}[^\s"]+)""",
    """"Mozilla\/[^"]+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin|iPhone OS|Mac OS)""",
    """Mozilla\/[^"]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """({top_domain}[^\/\.\s]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)(\s|\/|$)""",
  ]
}
```