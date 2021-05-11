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
    """devTime=({time}\w+ \d{1,100} \d{1,100} \d{1,100}:\d{1,100}:\d{1,100})""",
    """exabeam_host=({host}[\w.\-]+)""",
    """src=({src_ip}[a-fA-F\d:\.]+)""",
    """dst=(0\.0\.0\.0|({dest_ip}[a-fA-F\d:\.]+))""",
    """usrName=({user_email}[^\s@]+@[^=]+?)\s{0,100}\w+=""",
    """cat=({action}[^\s]+)""",
    """policy=({proxy_action}[^=]+?)\s{1,100}(\w+=|$)""",
    """urlcategory=({categories}({category}[^=]+?))\s{1,100}(\w+=|$)""",
    """url=({full_url}\S+)""",
    """url=(\w+:\/{2})?[^\/\s]+({uri_path}\/[^?\s]+)""",
    """url=(\w+:\/+)?[^|\/:\s]+(:\d{1,100})?[^|?\s]+({uri_query}\?[^\s]+)""",
    """url=(?:[^:?]+:\/+)?({web_domain}[^\/:\s]+)(:({dest_port}\d{1,100}))?""",
    """url=[^\s?=]*?({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^\.\s]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|link|cloud|news|fm|bz|goog|host|jetpack|ms|im|app|se)(?::\d{1,100})?)+(?:\s\w+=|\/|\s{1,100}$))[^\s:\/]*)""",
    """srcBytes=({bytes_out}\d{1,100})""",
    """dstBytes=({bytes_in}\d{1,100})""",
    """appproto=({protocol}[^=]+?)\s{1,100}(\w+=|$)""",
    """appname=({app}[^=]+?)\s{1,100}(\w+=|$)""",
    """useragent=(Unknown|({user_agent}[^=]+?))\s{1,100}(\w+=|$)""",
    """useragent=[^=]*?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
    """useragent=[^=]*?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """respcode=({result_code}\d{1,100})""",
    """reqmethod=(NA|({method}[^=]+?))\s{1,100}(\w+=|$)""",
    """fileclass=(None|({mime}[^=]+?))\s{1,100}(\w+=|$)""",
    """referer=(None|({referrer}.+?))\s{1,100}(\w+=|$)""",
    """riskscore=({risk_level}\d{1,100})""",
   ]
}
```