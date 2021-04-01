#### Parser Content
```Java
{
Name = q-zscaler-web-activity
  Vendor = Zscaler
  Product = Zscaler Internet Access
  Lms = QRadar
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """|Zscaler|NSS|""", """|cat=""" ]
  Fields = [
    """devTime=({time}\w+ \d+ \d+ \d+:\d+:\d+)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """src=({src_ip}[a-fA-F\d:\.]+)""",
    """dst=(0\.0\.0\.0|({dest_ip}[a-fA-F\d:\.]+))""",
    """usrName=({user_email}[^\s@]+@[^=]+?)\s*\w+=""",
    """cat=({action}[^\s]+)""",
    """policy=({proxy_action}[^=]+?)\s+(\w+=|$)""",
    """urlcategory=({categories}({category}[^=]+?))\s+(\w+=|$)""",
    """url=({full_url}\S+)""",
    """url=(\w+:\/{2})?[^\/\s]+({uri_path}\/[^?\s]+)""",
    """url=(\w+:\/+)?[^|\/:\s]+(:\d+)?[^|?\s]+({uri_query}\?[^\s]+)""",
    """url=(?:[^:?]+:\/+)?({web_domain}[^\/:\s]+)(:({dest_port}\d+))?""",
    """url=[^\s?=]*?({top_domain}(?!(?:\d+\.){3}\d+)[^\.\s]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|link|cloud|news|fm|bz|goog|host|jetpack|ms|im|app|se)(?::\d+)?)+(?:\s\w+=|\/|\s+$))[^\s:\/]*)""",
    """srcBytes=({bytes_out}\d+)""",
    """dstBytes=({bytes_in}\d+)""",
    """appproto=({protocol}[^=]+?)\s+(\w+=|$)""",
    """appname=({app}[^=]+?)\s+(\w+=|$)""",
    """useragent=(Unknown|({user_agent}[^=]+?))\s+(\w+=|$)""",
    """useragent=[^=]*?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
    """useragent=[^=]*?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """respcode=({result_code}\d+)""",
    """reqmethod=(NA|({method}[^=]+?))\s+(\w+=|$)""",
    """fileclass=(None|({mime}[^=]+?))\s+(\w+=|$)""",
    """referer=(None|({referrer}.+?))\s+(\w+=|$)""",
    """riskscore=({risk_level}\d+)""",
   ]
}
```