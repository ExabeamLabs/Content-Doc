#### Parser Content
```Java
{
Name = cws-proxy-1
    Vendor = Cisco
    Product = Cisco Cloud Web Security
    Lms = Direct
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "epoch_sec"
    Conditions = [ """ accesslogs: Info: """ ]
    Fields = [
      """({host}[\w.\-]+)\s+accesslogs:\s+Info:\s+({time}\d+)\.\d+\s+\S+\s+(-|({src_ip}[a-fA-F\d.:]+))\s+(NONE|({proxy_action}[^\s\/]+))\/({result_code}\d+)\s+\S+\s+(-|({method}\S+))\s+({full_url}(({protocol}\w+):\/+)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({web_domain}[^\s\/]*?({top_domain}[^\.\s]+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ch|local|aero|goog))+)?))(:({dest_port}\d+))?({uri_path}\/[^\s\?]*?)?({uri_query}\?[^\s]*?)?)((\s+(-|"(({domain}[^"\/\\@]+)[\\\/]+)?({user}[^\\\/@"]+)[^"]*")\s)|\s*$|\s)""",
      """\s<\w+_([^,]*,){22}"\s*({category}[^"]+?)\s*"""",
    ]
  }
```