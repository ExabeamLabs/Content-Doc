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
      """mwg: \[({time}\d+/\w+/\d\d\d\d:\d\d:\d\d:\d\d (\+|\-)\d+)\];\s*(|-|({user}[^;]+?));\s*(|({result_code}\d+));\s*(|({src_ip}[a-fA-F\d.:]+));\s*(|({dest_ip}[a-fA-F\d.:]+));\s*(|\(({web_domain}[^;]+?)\));\s*(|\(-\)|\(({referrer}[^;]+?)\));\s*(|\(({categories}({category}[^,;]+)[^;]*?)\));\s*(|({risk_level}[^;]+?));\s*(|({mime}[^;]+?));\s*(|({bytes_in}\d+));\s*(|({bytes_out}\d+));\s*(|-|({rule}[^;]+?));\s*(|({failure_reason}[^;]+?));([^;]*;){2}\s*(|\(({method}\w+)\s+({full_url}(\w+:/+)?[^;\/]*?({top_domain}(?!(?:\d+\.){3}\d+)[^\.\s;]+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ch|local))+)?(:({dest_port}\d+))?({uri_path}/[^;\?]*?)?({uri_query}\?[^;]*?)?)\s+\S+\));\s*(|({protocol}[^;]+?));\s*(|({user_agent}[^;]+?))(;|\s*$)""",
      """\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^;]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)[^;]*?\s*$"""
    ]
  }
```