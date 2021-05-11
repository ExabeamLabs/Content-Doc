#### Parser Content
```Java
{
Name = checkpoint-proxy
  Vendor = Check Point Software
  Product = Check Point NGFW
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "ddMMMyyyy HH:mm:ss"
  Conditions = [ """product: URL Filtering;""", """;i/f_name:""", """;user:""" ]
  Fields = [
    """\s({time}\d{1,100}\w{3}\d{1,100} \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]+)""",
    """dst:\s{1,100}(?:-|({dest_ip}[^;]+))""",
    """service:\s{1,100}(?:-|({dest_port}\d{1,100}));""",
    """src:\s{1,100}(?:-|({src_ip}[^;]+))""",
    """s_port:\s{1,100}(?:-|({src_port}\d{1,100}));""",
    """user:.+?\(({user}[^)]+)\)\s{1,100};web_client_type:""",
    """({action}[^\s]+)\s{1,100}[^\s]+ product: """,
    """sent_bytes:\s{1,100}(?:-|({bytes_out}\d{1,100}));""",
    """received_bytes:\s{1,100}(?:-|({bytes_in}\d{1,100}))""",
    """resource:\s{1,100}(-|({full_url}[^;]+));\s{0,100}(\w+:|$)""",
    """resource:\s{1,100}(?:-|({protocol}[^:]+))""",
    """appi_name:\s{1,100}({web_domain}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|[^;\/]+)""",
    """resource:\s{1,100}(?:-|(\w+:\/+[^\/]+\/({uri_path}[^?;]+)))""",
    """resource:\s{1,100}(?:-|(\w+:\/+[^?]+({uri_query}[^;]+)));sent_bytes:""",
    """web_client_type:\s{1,100}(?:-|({user_agent}[^;]+))""",
    """matched_category:\s{1,100}(?:-|({category}[^;]+))""",
    """app_properties:\s{1,100}(?:-|({category}[^,;]+)).*matched_category:\s{1,100}High Risk""",
    """web_client_type:\s{1,100}(Other: )?(?:-|({browser}[\w\-]+))""",
    """web_client_type:\s{1,100}(Other: )?(?:-|({browser}[\w\-]+)\/[\d\._]+)""",
    """web_client_type:\s{1,100}(Other: )?(?:-|({browser}[^\/;]+).+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
    """web_client_type:\s{1,100}(Other: )?(?:-|Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
    """web_client_type:\s{1,100}(Other: )?(?:-|Mozilla\/.+\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+Gecko\/\d{1,100}\s{1,100}({browser}\w+))""",
    """appi_name:(.*?)({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^\.\s]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+(;|\/))[^;\/]+)"""
  ]
}
```