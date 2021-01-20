#### Parser Content
```Java
{
Name = iis-web-activity-1
  Vendor = Microsoft
  Product = IIS
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """<custom_conditions-cont-6904>""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\d+-\d+-\d+\s+\d+:\d+:\d+)\s+({dest_ip}[A-Fa-f:\d.]+)\s+(-|({method}\S+))\s+(-|({uri_path}\/\S*))\s+(-|({uri_query}\S+))\s+({dest_port}\d+)\s+(-|(({domain}[^\\\s]+)\\+)?({user}[^\\\s]+))\s+({src_ip}[A-Fa-f:\d.]+)\s+(-|({user_agent}.+?))\s+(-|({referrer}\S+))\s+({web_domain}[\w\-.]+)\s+({result_code}\d+)\s+\d+\s+\d+\s+\d+""",
    """Mozilla\/[^="]+?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]*?\s+\S+(\s+\d+){4}""",
    """Mozilla\/[^="]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)[^"]*?\s+\S+(\s+\d+){4}""",
    """\s[^\/"\s:]*?({top_domain}[^\.\/\s":]+(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)\s+(\d+\s+){4}""",
  ]
}
```