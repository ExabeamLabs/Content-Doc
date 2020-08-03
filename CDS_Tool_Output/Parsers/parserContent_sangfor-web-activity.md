#### Parser Content
```Java
{
Name = sangfor-web-activity
  Vendor = Sangfor
  Product = NGAF
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ssZ"
  Conditions = [ """type: website browsing""", """<Identifier>ZC01_NTTDHK-FWL-002</Identifier>""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d[\+\-]\d+:\d+)\s+\S+\s+fwlog:""",
    """<Identifier>ZC01_({host}[\w\-.]+)<\/Identifier>""",
    """user:\s*\((null|({user}[^\s\)]+))\)""",
    """policy name:\s*({policy}[^,"]+)""",
    """Src IP:\s*({src_ip}[A-Fa-f:\d.]+)""",
    """Dst IP:\s*({dest_ip}[A-Fa-f:\d.]+)""",
    """application:\s*({categories}({category}[^;,"]+)[^,]*)""",
    """action:\s*({action}[^,"]+)""",
    """URL:\s*(-|({full_url}(({protocol}[^:\\\/\s,"]+):[\\\/]+)?({web_domain}[^\\\/\s:,"]+)(:({dest_port}\d+))?({uri_path}\/[^\s\?",]*)?({uri_query}\?[^"\s]*)?))"""",
    """URL:\s*[^"\s]*?({top_domain}[^\\\/\s\.:,;"]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|pl|nl|es|gr|cz|eu|tv|me|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ai|am|be|bid|blog|bot|ch|cloud|ec|goog|hosting|il|im|la|link|live|ly|market|media|mobi|ms|network|ninja|pe|ph|place|pro|se|site|space|stream|tech|to|top|ua|vc|video|watch|ws|wtf|xyz|zone|local|services|gl|ad|ag|aero|technology|marketing|page|pub|report|tg|uy|ae|corp|afg|by|mx|tr|fmx|as|ke|fm|br|aws|host|jetpack|app|hk|google))+)(:|\s|\/|")""",
  ]
  DupFields = [ "action->outcome" ]
}
```