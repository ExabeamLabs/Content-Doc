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
    """exabeam_host=({host}[^\s]{1,2000})""",
    """dst:\s{1,100}(?:-|({dest_ip}[^;]{1,2000}))""",
    """service:\s{1,100}(?:-|({dest_port}\d{1,100}));""",
    """src:\s{1,100}(?:-|({src_ip}[^;]{1,2000}))""",
    """s_port:\s{1,100}(?:-|({src_port}\d{1,100}));""",
    """user:.+?\(({user}[^)]{1,2000})\)\s{1,100};web_client_type:""",
    """({action}[^\s]{1,2000})\s{1,100}[^\s]{1,2000} product: """,
    """sent_bytes:\s{1,100}(?:-|({bytes_out}\d{1,100}));""",
    """received_bytes:\s{1,100}(?:-|({bytes_in}\d{1,100}))""",
    """resource:\s{1,100}(-|({full_url}[^;]{1,2000}));\s{0,100}(\w+:|$)""",
    """resource:\s{1,100}(?:-|({protocol}[^:]{1,2000}))""",
    """appi_name:\s{1,100}({web_domain}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|[^;\/]{1,2000})""",
    """resource:\s{1,100}(?:-|(\w+:\/+[^\/]{1,2000}\/({uri_path}[^?;]{1,2000})))""",
    """resource:\s{1,100}(?:-|(\w+:\/+[^?]{1,2000}({uri_query}[^;]{1,2000})));sent_bytes:""",
    """web_client_type:\s{1,100}(?:-|({user_agent}[^;]{1,2000}))""",
    """matched_category:\s{1,100}(?:-|({category}[^;]{1,2000}))""",
    """app_properties:\s{1,100}(?:-|({category}[^,;]{1,2000})).*matched_category:\s{1,100}High Risk""",
    """web_client_type:\s{1,100}(Other: )?(?:-|({browser}[\w\-]{1,2000}))""",
    """web_client_type:\s{1,100}(Other: )?(?:-|({browser}[\w\-]{1,2000})\/[\d\._]{1,2000})""",
    """web_client_type:\s{1,100}(Other: )?(?:-|({browser}[^\/;]{1,2000}).+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
    """web_client_type:\s{1,100}(Other: )?(?:-|Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
    """web_client_type:\s{1,100}(Other: )?(?:-|Mozilla\/.+\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+Gecko\/\d{1,100}\s{1,100}({browser}\w+))""",
    """appi_name:(.*?)({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^\.\s]{1,2000}(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+(;|\/))[^;\/]{1,2000})"""
  ]
}
```