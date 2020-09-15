#### Parser Content
```Java
{
Name = edgewave-web-activity
  Vendor = EdgeWave
  Product = EdgeWave iPrism
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Conditions = [ """ iPrism[""", """]: WEB""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """Original Address=({src_ip}[A-Fa-f:\d.]+)""",
    """\]: WEB\s+({protocol}\S+)\s+({time}\d+)\s+({outcome}\S+)\s+({dest_ip}[A-Fa-f:\d.]+)\s+({proxy_action}\S+)\s+(\[[^\]]*\]|((({domain}[^\\\s\[\]]+)\\+)?({user}[^\\\s\[\]]+)))\s+\S+\s+({categories}({category}[^;,]+).*?)\s+\d+\s+({method}\S+)\s+({result_code}\d+)\s+\S+\s+(-|({full_url}(({=protocol}[^:\\\/\s,"]+):[\\\/]+)?({web_domain}[^\\\/\s:,"]+)?(:({dest_port}\d+))?({uri_path}\/[^\s\?",]*)?({uri_query}\?[^"\s,]*)?))\s+$""",
    """\]: WEB.*?\s+[^\s]*?({top_domain}[^\/\.\s]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ai|am|be|bid|blog|bot|ch|cloud|ec|goog|hosting|il|im|la|link|live|ly|market|media|mobi|ms|network|ninja|pe|ph|place|pro|se|site|space|stream|tech|to|top|ua|vc|video|watch|ws|wtf|xyz|zone))+)(\/|:|\s)\S*\s+(\w+=|$)""",
  ]
}
```