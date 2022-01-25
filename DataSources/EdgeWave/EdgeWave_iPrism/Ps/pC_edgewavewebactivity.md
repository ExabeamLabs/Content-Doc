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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """Original Address=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\]: WEB\s{1,100}({protocol}\S+)\s{1,100}({time}\d{1,100})\s{1,100}({outcome}\S+)\s{1,100}({dest_ip}[A-Fa-f:\d.]{1,2000})\s{1,100}({proxy_action}\S+)\s{1,100}(\[[^\]]{0,2000}\]|((({domain}[^\\\s\[\]]{1,2000})\\+)?({user}[^\\\s\[\]]{1,2000})))\s{1,100}\S+\s{1,100}({categories}({category}[^;,]{1,2000}).*?)\s{1,100}\d{1,100}\s{1,100}({method}\S+)\s{1,100}({result_code}\d{1,100})\s{1,100}\S+\s{1,100}(-|({full_url}(({=protocol}[^:\\\/\s,"]{1,2000}):[\\\/]{1,2000})?({web_domain}[^\\\/\s:,"]{1,2000})?(:({dest_port}\d{1,100}))?({uri_path}\/[^\s\?",]{0,2000})?({uri_query}\?[^"\s,]{0,2000})?))\s{1,100}$""",
    """\]: WEB.*?\s{1,100}[^\s]{0,2000}?({top_domain}[^\/\.\s]{1,2000}(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ai|am|be|bid|blog|bot|ch|cloud|ec|goog|hosting|il|im|la|link|live|ly|market|media|mobi|ms|network|ninja|pe|ph|place|pro|se|site|space|stream|tech|to|top|ua|vc|video|watch|ws|wtf|xyz|zone))+)(\/|:|\s)\S*\s{1,100}(\w+=|$)""",
  ]


}
```