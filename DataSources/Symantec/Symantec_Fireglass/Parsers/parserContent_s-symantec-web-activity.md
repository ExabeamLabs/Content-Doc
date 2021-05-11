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
    """@timestamp:\s{0,100}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """\Whost:\s{0,100}({host}[^\s,]+)""",
    """\Wtop_level_url_host:\s{0,100}({top_domain}[^,]+)""",
    """\Wtop_level_url_scheme:\s{0,100}({protocol}[^,]+)""",
    """\Wusername:\s{0,100}({user_email}[^,\s]+)""",
    """\Wdestination_ip:\s{0,100}({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wurl_port:\s{0,100}({dest_port}\d{1,100})""",
    """\Wurl_host:\s{0,100}({web_domain}[^,]+)""",
    """\Wresponse_status_code:\s{0,100}({result_code}\d{1,100})""",
    """\Wurl:\s{0,100}"({full_url}[^",]+)""",
    """\Wurl:\s{0,100}"{0,20}(?:-|\w+:\/+[^\/]+)({uri_path}\/[^?\s"]+)""",
    """\Wurl:\s{0,100}"{0,20}(?:-|(?=(?)(?:[^?]+({uri_query}\?[^\s"]+))))""",
    """\Wrequest_method:\s{0,100}({method}[^,]+)""",
    """\Wclient_name:\s{0,100}({browser}[^,]+)""",
    """\Wcontent_type:\s{0,100}({mime}[^,]+)""",
    """\Waction:\s{0,100}({action}[^,]+)""",
    """\Wurl_categories:\s{0,100}\[(|({categories}[^\]]+))""",
    """\Wurl_categories:\s{0,100}\[(|({category}[^,;\]]+))""",
    """\Wsource_ip:\s{0,100}({src_translated_ip}[A-Fa-f:\d.]+)""",
    """\Woriginal_source_ip:\s{0,100}({src_ip}[A-Fa-f:\d.]+)""",
    """\Wuser_agent:\s{0,100}({user_agent}[^,]+)""",
    """\Wclient_os_name:\s{0,100}({os}[^,]+)""",
    """\Wreferer_url:\s{0,100}({referrer}[^,\}]+)""",
    """\Wmalicious:\s{0,100}({malicious}[^,]+)""",
  ]
}
```