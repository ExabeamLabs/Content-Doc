#### Parser Content
```Java
{
Name = q-zscaler-web-activity
  Vendor = Zscaler
  Lms = QRadar
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """|Zscaler|NSS|""", """|cat=""" ]
  Fields = [
    """(\s|\|)devTime=({time}\w+ \d+ \d+ \d+:\d+:\d+)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """(\s|\|)src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\w+=|$)""",
    """(\s|\|)dst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\w+=|$)""",
    """(\s|\|)usrName=({user}[^\s@>]+)\s+(\w+=|$)""",
    """(\s|\|)usrName=({user_email}[^\s@]+@[^\s]+)\s+(\w+=|$)""",
    """(\s|\|)cat=({action}.+?)\s+(\w+=|$)""",
    """(\s|\|)policy=({proxy_action}.+?)\s+(\w+=|$)""",
    """(\s|\|)urlcategory=({categories}({category}[^,;=\t]+).*?)\s+(\w+=|$)""",
    """(\s|\|)url=({full_url}\S+)""",
    """(\s|\|)url=(\w+:\/{2})?[^\/\s]+({uri_path}\/[^?\s]+)""",
    """(\s|\|)url=(\w+:\/+)?[^|\/:\s]+(:\d+)?[^|?\s]+({uri_query}\?[^\s]+)""",
    """(\s|\|)url=(?:[^:?]+:\/+)?({web_domain}[^\/:\s]+)(:({dest_port}\d+))?""",
    """(\s|\|)url=[^\s?=]*?({top_domain}(?!(?:\d+\.){3}\d+)[^\.\s]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|link|cloud|news|fm|bz|goog|host|jetpack|ms|im|app|se)(?::\d+)?)+(?:\s\w+=|\/|\s+$))[^\s:\/]*)""",
    """(\s|\|)srcBytes=({bytes_out}\d+)\s+(\w+=|$)""",
    """(\s|\|)dstBytes=({bytes_in}\d+)\s+(\w+=|$)""",
    """(\s|\|)appproto=({protocol}.+?)\s+(\w+=|$)""",
    """(\s|\|)useragent=(Unknown|({user_agent}.+?))\s+(\w+=|$)""",
    """(\s|\|)useragent=[^=]*?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
    """(\s|\|)useragent=[^=]*?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """(\s|\|)respcode=({result_code}\d+)""",
    """(\s|\|)reqmethod=({method}.+?)\s+(\w+=|$)""",
    """(\s|\|)fileclass=(None|({mime}.+?))\s+(\w+=|$)""",
    """(\s|\|)referer=(None|({referrer}.+?))\s+(\w+=|$)""",
  ]
}
```