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
  ]


}
```