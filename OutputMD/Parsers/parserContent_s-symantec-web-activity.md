#### Parser Content
```Java
{
Name = s-symantec-web-activity
  Vendor = Symantec
  Product = Symantec Fireglass
  Lms = Splunk
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """, url_categories:""", """, top_level_url_host:""", """, top_level_url_scheme:""", """, malicious:"""]
  Fields = [
    """@timestamp:\s*({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """\Whost:\s*({host}[^\s,]+)""",
    """\Wtop_level_url_host:\s*({top_domain}[^,]+)""",
    """\Wtop_level_url_scheme:\s*({protocol}[^,]+)""",
    """\Wusername:\s*({user_email}[^,\s]+)""",
    """\Wdestination_ip:\s*({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wurl_port:\s*({dest_port}\d+)""",
    """\Wurl_host:\s*({web_domain}[^,]+)""",
    """\Wresponse_status_code:\s*({result_code}\d+)""",
    """\Wurl:\s*"({full_url}[^",]+)""",
    """\Wurl:\s*"*(?:-|\w+:\/+[^\/]+)({uri_path}\/[^?\s"]+)""",
    """\Wurl:\s*"*(?:-|(?=(?)(?:[^?]+({uri_query}\?[^\s"]+))))""",
    """\Wrequest_method:\s*({method}[^,]+)""",
    """\Wclient_name:\s*({browser}[^,]+)""",
    """\Wcontent_type:\s*({mime}[^,]+)""",
    """\Waction:\s*({action}[^,]+)""",
    """\Wurl_categories:\s*\[(|({categories}[^\]]+))""",
    """\Wurl_categories:\s*\[(|({category}[^,;\]]+))""",
    """\Wsource_ip:\s*({src_translated_ip}[A-Fa-f:\d.]+)""",
    """\Woriginal_source_ip:\s*({src_ip}[A-Fa-f:\d.]+)""",
    """\Wuser_agent:\s*({user_agent}[^,]+)""",
    """\Wclient_os_name:\s*({os}[^,]+)""",
    """\Wreferer_url:\s*({referrer}[^,\}]+)""",
    """\Wmalicious:\s*({malicious}[^,]+)""",
  ]
}
```