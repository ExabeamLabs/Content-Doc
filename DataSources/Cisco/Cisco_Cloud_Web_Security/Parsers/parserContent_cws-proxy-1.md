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
      """({host}[\w.\-]+)\s{1,100}accesslogs:\s{1,100}Info:\s{1,100}({time}\d{1,100})\.\d{1,100}\s{1,100}\S+\s{1,100}(-|({src_ip}[a-fA-F\d.:]+))\s{1,100}(NONE|({proxy_action}[^\s\/]+))\/({result_code}\d{1,100})\s{1,100}\S+\s{1,100}(-|({method}\S+))\s{1,100}({full_url}(({protocol}\w+):\/+)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({web_domain}[^\s\/]*?({top_domain}[^\.\s]+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ch|local|aero|goog))+)?))(:({dest_port}\d{1,100}))?({uri_path}\/[^\s\?]*?)?({uri_query}\?[^\s]*?)?)((\s{1,100}(-|"(({domain}[^"\/\\@]+)[\\\/]+)?({user}[^\\\/@"]+)[^"]*")\s)|\s{0,100}$|\s)""",
      """\s<\w+_([^,]*,){22}"\s{0,100}({category}[^"]+?)\s{0,100}"""",
    ]
  }
```