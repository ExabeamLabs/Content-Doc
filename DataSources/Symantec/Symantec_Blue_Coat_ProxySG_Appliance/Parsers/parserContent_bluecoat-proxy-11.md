#### Parser Content
```Java
{
Name = bluecoat-proxy-11
  DataType = "network-connection"
  Conditions = [ """ PROXIED """, """ TCP_""" ]
  Fields = ${BlueCoatParserTemplates.bluecoat-proxy.Fields}[
    """(-|({failure_reason}\S+))\s{1,100}PROXIED"""
  ]
}
bluecoat-proxy = {
  Vendor = Symantec
  Product = Symantec Blue Coat ProxySG Appliance
  Lms = Splunk
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+?@\s{0,100})?({host}[^\s]+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\S*\s{1,100}[\w\-.]+\s{1,100}Skyformation""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)\s{1,100}\d{1,100}\s{1,100}(?:-|({src_ip}[^\s]+))\s{1,100}(\S+\s{1,100})?(?:-|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\d{1,100}|TUNNELED|DENIED|({user}[^\s\_]+))\s""",
    """\s\d{1,100}\s({src_ip}\d{1,100}.\d{1,100}.\d{1,100}.\d{1,100})\s{1,100}(-|non-interactive-user|((({domain}[^\\]+)\\)?({user}[^\s]+)))\s{1,100}([^\s]+\s){2}({action}OBSERVED|PROXIED|DENIED)""",
    """({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s([^\s]+\s){3}({action}OBSERVED|PROXIED|DENIED)""",
    """({dest_ip}\d{1,100}\.\d{1,100}\.\d{1,100}\.\d{1,100})\s{0,100}$""",
    """({action}OBSERVED|PROXIED|DENIED)\s{1,100}(?:-|"(none|({category}[^"]+))")\s{1,100}(?:-|({referrer}[^\s]+))\s{1,100}(?:-|({result_code}[^\s]+))\s{1,100}(?:-|({proxy_action}[^\s]+))\s{1,100}(?:-|unknown|({method}[^\s]+))\s{1,100}(?:-|({mime}[^\s]+))\s{1,100}((?:({dest_ip}\d{1,100}\.\d{1,100}\.\d{1,100}\.\d{1,100}))\s{1,100})?(?:-|({protocol}[^\s]+))\s{1,100}(?:-|({web_domain}(?:({=dest_ip}\d{1,100}\.\d{1,100}\.\d{1,100}\.\d{1,100})|[^\s]+)))\s{1,100}(?:-|({dest_port}\d{1,100}))\s{1,100}(?:-|\/|({uri_path}[^\s]+))\s{1,100}(({=dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s{1,100})?(?:-|({uri_query}[^\s]+))\s{1,100}\S+\s{1,100}(?:-|"({user_agent}[^"]+)")\s{1,100}(?:-|({host}[^\s]+))\s{1,100}(?:-|({bytes_out}\d{1,100}))\s{1,100}(?:-|({bytes_in}\d{1,100}))\s{1,100}("{0,20}[^"]*"{0,20}\s{1,100}){3}(?:-|({=dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))\s{1,100}""",
    """(?:-|({host}[^\s]+))\s{1,100}(?:-|({src_port}\d{1,100}))\s{1,100}(?:-|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({user}[^\s]+))\s{1,100}(?:-|({bytes_in}\d{1,100}))\s{1,100}(?:-|({bytes_out}\d{1,100}))\s{1,100}(\S+\s{1,100}){3}(?:-|({result_code}[^\s]+))\s{1,100}({action}OBSERVED|PROXIED|DENIED)\s{1,100}(?:-|"(none|({category}[^"]+))")\s{1,100}(?:-|"[^"]*")\s{1,100}(?:-|({referrer}[^\s]+))\s{1,100}(?:-|({proxy_action}[^\s]+))\s{1,100}(?:-|unknown|({method}[^\s]+))\s{1,100}(?:-|({mime}[^\s]+))\s{1,100}(?:-|"(none|({user_agent}[^"]+))")\s{1,100}(?:-|({protocol}[^\s]+))\s{1,100}(?:-|({web_domain}[^\s\.]+(\.[^\s\.]+)+)|\S+)\s{1,100}(?:-|({dest_port}\d{1,100})|\S+)\s{1,100}(?:-|\/|({uri_path}[^\s]+))\s{1,100}(?:-|({uri_query}[^\s]+))\s{1,100}\S+\s{1,100}(?:-|({full_url}[^\s]+))\s""",
    """({action}OBSERVED|PROXIED|DENIED)\s{1,100}(?:-|\\?"(none|({category}[^"]+?))\\?")\s{1,100}(?:-|({referrer}[^\s]+))\s{1,100}(?:-|({result_code}[^\s]+))\s{1,100}(?:-|({proxy_action}[^\s]+))\s{1,100}(?:-|unknown|({method}[^\s]+))\s{1,100}(?:-|({mime}[^\s]+))\s{1,100}(?:-|({protocol}[^\s]+))\s{1,100}(?:-|({web_domain}(?:({dest_ip}\d{1,100}\.\d{1,100}\.\d{1,100}\.\d{1,100})|[\w\-.]+)))\s{1,100}(?:-|0|({dest_port}\d{1,100}))\s{1,100}(?:-|\/|({uri_path}\/[^\s]*?))\s{1,100}(?:-|({uri_query}[^\s]+))\s{1,100}\S+\s{1,100}(?:-|\\?"{0,20}({user_agent}[^"]+?)\\?"{0,20})\s{1,100}(?:-|({host}[^\s]+))\s{1,100}(?:-|({bytes_out}\d{1,100}))\s{1,100}(?:-|({bytes_in}\d{1,100}))\s{1,100}("{0,20}[^"]*"{0,20}\s{1,100}){5}(?:-|({=dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))\s{1,100}""",
    """\s({result_code}\d{1,100})\s{1,100}({proxy_action}\S+)\s{1,100}({bytes_out}\d{1,100})\s{1,100}({bytes_in}\d{1,100})\s{1,100}({method}\S+)\s{1,100}({protocol}\S+)\s{1,100}({web_domain}\S+)\s{1,100}(-|({full_url}(({=protocol}[^:\\\/\s,"]+):[\\\/]+)?[\\\/]*(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({=web_domain}[^\\\/\s:,"]+))(:({dest_port}\d{1,100}))?(\/|({uri_path}\/[^\s\?",]*))?({uri_query}\?[^"\s]*)?))\s{1,100}(-|({user}[^\s]+))\s{1,100}\S+\s{1,100}(({=dest_ip}[A-Fa-f:\d.]+)|({=web_domain}[\w\-.]+))\s{1,100}(-|({mime}\S+))\s{1,100}"({user_agent}[^"]+)"\s{1,100}({action}OBSERVED|PROXIED|DENIED)""",
    """:\d\d:\d\d\s{1,100}\d{1,100}\s(-|({src_ip}[A-Fa-f:\d.]+))\s{1,100}(-|({result_code}\d{1,100}))\s{1,100}(-|({proxy_action}\S+))\s{1,100}(-|({bytes_out}\d{1,100}))\s{1,100}(-|({bytes_in}\d{1,100}))\s{1,100}(-|unknown|({method}\S+))\s{1,100}(-|({protocol}\S+))\s{1,100}(-|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({web_domain}[^\s]+))\s{1,100}(-|({dest_port}\d{1,100}))\s{1,100}(-|\/|({uri_path}[^\s]+))\s{1,100}(-|({uri_query}\S+))\s{1,100}(-|({user}\S+))(\s{1,100}\S+){2}\s{1,100}((-|({dest_ip}[\da-fA-F.:]+))(\s{1,100}(\S+|"[^"]*")){2}\s{1,100})?(-|({mime}[^\s]+))\s{1,100}\S+\s{1,100}(-|"({user_agent}[^"]+)")\s{1,100}({action}OBSERVED|PROXIED|DENIED)\s{1,100}"{0,20}(-|none|({categories}({category}[^",;:]{1,30})[^"]{0,200}))"{0,20}\s""",
    """({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)\s\d{1,100}\s({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s(-|({user}[^\s]+)\s).*?\s.*?({action}OBSERVED|PROXIED|DENIED)\s{1,100}\\*"{0,20}(?:-|\\?"(none|({category}[^\\"]+))\\?"{0,20})\s{1,100}(?:-|({referrer}[^\s]+))\s{1,100}(?:-|({result_code}[^\s]+))\s{1,100}(?:-|({proxy_action}[^\s]+))\s{1,100}(?:-|unknown|({method}[^\s]+))\s{1,100}(?:-|({mime}[^\s]+))\s{1,100}(?:-|({protocol}[^\s]+))\s{1,100}(?:-|({web_domain}(?:({dest_ip}\d{1,100}\.\d{1,100}\.\d{1,100}\.\d{1,100})|[\w\-.]+)))\s{1,100}(?:-|0|({dest_port}\d{1,100}))\s{1,100}(?:-|\/|({uri_path}[^\s]*?))\s{1,100}(?:-|({uri_query}[^\s]+))\s{1,100}\S+\s{1,100}(?:-|\\*"{0,20}({user_agent}[^"]+)\\*"{0,20})\s{1,100}(?:-|({host}[^\s]+))\s{1,100}(?:-|({bytes_out}\d{1,100}))\s{1,100}(?:-|({bytes_in}\d{1,100}))\s""",
    """(http|https|tcp|ssl)\s{1,100}\S*?({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^\.\s]+?(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ch|local|ad|al|aws|be|br|cl|goog|gt|im|la|live|market|ms|mx|name|network|no|pub|to|ai|cloud|th|vn))+)\s""",
    """"(?:-|Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
  ]

```