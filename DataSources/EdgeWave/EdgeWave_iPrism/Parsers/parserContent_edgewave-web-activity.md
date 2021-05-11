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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """Original Address=({src_ip}[A-Fa-f:\d.]+)""",
    """\]: WEB\s{1,100}({protocol}\S+)\s{1,100}({time}\d{1,100})\s{1,100}({outcome}\S+)\s{1,100}({dest_ip}[A-Fa-f:\d.]+)\s{1,100}({proxy_action}\S+)\s{1,100}(\[[^\]]*\]|((({domain}[^\\\s\[\]]+)\\+)?({user}[^\\\s\[\]]+)))\s{1,100}\S+\s{1,100}({categories}({category}[^;,]+).*?)\s{1,100}\d{1,100}\s{1,100}({method}\S+)\s{1,100}({result_code}\d{1,100})\s{1,100}\S+\s{1,100}(-|({full_url}(({=protocol}[^:\\\/\s,"]+):[\\\/]+)?({web_domain}[^\\\/\s:,"]+)?(:({dest_port}\d{1,100}))?({uri_path}\/[^\s\?",]*)?({uri_query}\?[^"\s,]*)?))\s{1,100}$""",
    """\]: WEB.*?\s{1,100}[^\s]*?({top_domain}[^\/\.\s]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ai|am|be|bid|blog|bot|ch|cloud|ec|goog|hosting|il|im|la|link|live|ly|market|media|mobi|ms|network|ninja|pe|ph|place|pro|se|site|space|stream|tech|to|top|ua|vc|video|watch|ws|wtf|xyz|zone))+)(\/|:|\s)\S*\s{1,100}(\w+=|$)""",
  ]
}
```