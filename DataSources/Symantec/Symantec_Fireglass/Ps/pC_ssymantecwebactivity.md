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
    """\Whost:\s{0,100}({host}[^\s,]{1,2000})""",
    """\Wtop_level_url_host:\s{0,100}({top_domain}[^,]{1,2000})""",
    """\Wtop_level_url_scheme:\s{0,100}({protocol}[^,]{1,2000})""",
    """\Wusername:\s{0,100}({user_email}[^,\s]{1,2000})""",
    """\Wdestination_ip:\s{0,100}({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wurl_port:\s{0,100}({dest_port}\d{1,100})""",
    """\Wurl_host:\s{0,100}({web_domain}[^,]{1,2000})""",
    """\Wresponse_status_code:\s{0,100}({result_code}\d{1,100})""",
    """\Wurl:\s{0,100}"({full_url}[^",]{1,2000})""",
    """\Wurl:\s{0,100}"{0,20}(?:-|\w+:\/+[^\/]{1,2000})({uri_path}\/[^?\s"]{1,2000})""",
    """\Wurl:\s{0,100}"{0,20}(?:-|(?=(?)(?:[^?]{1,2000}({uri_query}\?[^\s"]{1,2000}))))""",
    """\Wrequest_method:\s{0,100}({method}[^,]{1,2000})""",
    """\Wclient_name:\s{0,100}({browser}[^,]{1,2000})""",
    """\Wcontent_type:\s{0,100}({mime}[^,]{1,2000})""",
    """\Waction:\s{0,100}({action}[^,]{1,2000})""",
    """\Wurl_categories:\s{0,100}\[(|({categories}[^\]]{1,2000}))""",
    """\Wurl_categories:\s{0,100}\[(|({category}[^,;\]]{1,2000}))""",
    """\Wsource_ip:\s{0,100}({src_translated_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Woriginal_source_ip:\s{0,100}({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wuser_agent:\s{0,100}({user_agent}[^,]{1,2000})""",
    """\Wclient_os_name:\s{0,100}({os}[^,]{1,2000})""",
    """\Wreferer_url:\s{0,100}({referrer}[^,\}]{1,2000})""",
    """\Wmalicious:\s{0,100}({malicious}[^,]{1,2000})""",
  ]
}
```