#### Parser Content
```Java
{
Name = checkpoint-proxy-1
  Vendor = Check Point
  Product = Check Point NGFW
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "ddMMMyyyy HH:mm:ss"
  Conditions = [ """product: URL Filtering;""", """;i/f_name:""", """;src_user_name:""" ]
  Fields = [
    """^[^;]*?({time}\d+\w{3}\d+ \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]+)""",
    """src_machine_name:\s*({host}[^@;]+)(@({domain}\w+))?""",
    """dst:\s+(?:-|({dest_ip}[^;]+))""",
    """service:\s+(?:-|({dest_port}\d+));""",
    """src:\s+(?:-|({src_ip}[^;]+))""",
    """s_port:\s+(?:-|({src_port}\d+));""",
    """src_user_name:\s*({user_lastname}[^,]+),\s*({user_firstname}[\w\s]+\S)\s*(\(|$)""",
    """({action}[^\s]+)\s+[^\s]+ product: """,
    """sent_bytes:\s+(?:-|({bytes_out}\d+));""",
    """received_bytes:\s+(?:-|({bytes_in}\d+))""",
    """resource:\s+(-|({full_url}[^;]+));\s*(\w+:|$)""",
    """resource:\s+(?:-|({protocol}[^:]+))""",
    """appi_name:\s+({web_domain}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|[^;\/]+)""",
    """resource:\s+(?:-|(\w+:\/+[^\/]+\/({uri_path}[^?;]+)))""",
    """resource:\s+(?:-|(\w+:\/+[^?]+\?({uri_query}[^;]+)));""",
    """matched_category:\s+(?:-|({category}[^;]+))""",
    """app_properties:\s+(?:-|({category}[^,;]+));""",
    """appi_name:(.*?)({top_domain}(?!(?:\d+\.){3}\d+)[^\.\s]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+(;|\/))[^;\/]+)"""
  ]
}
```