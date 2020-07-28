#### Parser Content
```Java
{
Name = iis-web-activity
  Vendor = Microsoft
  Product = IIS
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """<custom_conditions-cont-6864>""" ]
  Fields = [
    """({time}\d+-\d+-\d+\s+\d+:\d+:\d+)\s+({host}[\w\-.]+)\s+({dest_host}[\w\-.]+)\s+({dest_ip}[A-Fa-f:\d.]+)\s+({method}[^\s]+)\s+(-|({uri_path}\/[^\s]*))\s+(-|({uri_query}[^\s]*))\s+({dest_port}\d+)\s+(-|({user}[^\s]+))\s+({src_ip}[A-Fa-f:\d.]+)\s+\S+\s+({user_agent}.*?)\s+\S+\s+(-|({referrer}[^\s]+))\s+({web_domain}[\w\-.]+)\s+({result_code}\d+)\s+\d+\s+\d+\s+({bytes_out}\d+)\s+({bytes_in}\d+)\s+(\d+\s+(-|({=src_ip}[A-Fa-f:\d.]+))\s+)?""",
    """\d+-\d+-\d+\s+\d+:\d+:\d+\s+(\S+\s+){10}Mozilla\/[^="]+?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
    """\d+-\d+-\d+\s+\d+:\d+:\d+\s+(\S+\s+){10}Mozilla\/[^="]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """\s[^\/"\s:]*?({top_domain}[^\.\/\s":]+(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)\s+(\d+\s+){6}\S+\s+\S+\s+$""",
  ]
}
```