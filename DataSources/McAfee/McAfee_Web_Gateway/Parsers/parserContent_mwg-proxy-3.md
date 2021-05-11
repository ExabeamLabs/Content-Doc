#### Parser Content
```Java
{
Name = mwg-proxy-3
    Vendor = McAfee
    Product = McAfee Web Gateway
    Lms = Direct
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "dd/MMM/yyyy:HH:mm:ss Z"
    Conditions = [ """mwg: [""", """);""" ]
    Fields = [
      """exabeam_host=({host}[\w.\-]+)""",
      """mwg: \[({time}\d{1,100}/\w+/\d\d\d\d:\d\d:\d\d:\d\d (\+|\-)\d{1,100})\];\s{0,100}(|-|({user}[^;]+?));\s{0,100}(|({result_code}\d{1,100}));\s{0,100}(|({src_ip}[a-fA-F\d.:]+));\s{0,100}(|({dest_ip}[a-fA-F\d.:]+));\s{0,100}(|\(({web_domain}[^;]+?)\));\s{0,100}(|\(-\)|\(({referrer}[^;]+?)\));\s{0,100}(|\(({categories}({category}[^,;]+)[^;]*?)\));\s{0,100}(|({risk_level}[^;]+?));\s{0,100}(|({mime}[^;]+?));\s{0,100}(|({bytes_in}\d{1,100}));\s{0,100}(|({bytes_out}\d{1,100}));\s{0,100}(|-|({rule}[^;]+?));\s{0,100}(|({failure_reason}[^;]+?));([^;]*;){2}\s{0,100}(|\(({method}\w+)\s{1,100}({full_url}(\w+:/+)?[^;\/]*?({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^\.\s;]+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ch|local))+)?(:({dest_port}\d{1,100}))?({uri_path}/[^;\?]*?)?({uri_query}\?[^;]*?)?)\s{1,100}\S+\));\s{0,100}(|({protocol}[^;]+?));\s{0,100}(|({user_agent}[^;]+?))(;|\s{0,100}$)""",
      """\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^;]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)[^;]*?\s{0,100}$"""
    ]
  }
```