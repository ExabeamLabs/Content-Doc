#### Parser Content
```Java
{
Name = s-mwg-proxy
  Vendor = McAfee
  Product = McAfee Web Gateway
  Lms = Splunk
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """mwg: status="""", """srcip="""", """mtd="""", """urlp="""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d\s{1,100}({host}[^\s]{1,2000})\s{1,100}mwg:""",
    """\Wstatus="({result_code}\d{1,100})""",
    """\Wsrcip="(|({src_ip}[^"]{1,2000}))"""",
    """\Wuser="(-|({user}[^"]{1,2000}))"""",
    """\Wdst_ip="(-|({dest_ip}[^"]{1,2000}))"""",
    """\Wurlp="(-|({dest_port}\d{1,100}))""",
    """\Wproto="(-|({protocol}[^"]{1,2000}))"""",
    """\Wmtd="(-|({method}[^"]{1,2000}))"""",
    """\Wurlc="(-|({category}[^"]{1,2000}))"""",
    """\Wmt="(-|({mime}[^"]{1,2000}))"""",
    """\Wbytes="(-|({bytes_in}\d{1,100})\/({bytes_out}\d{1,100})\/({bytes_in_post}\d{1,100})\/({bytes_in_get}\d{1,100}))"""",
    """\Wua="(-|({user_agent}[^"]{1,2000}))"""",
    """\Wrule="(-|({proxy_action}[^"]{1,2000}))"""",
    """\Wurl="(-|({full_url}[^"]{1,2000}))"""",
    """\Wurl="(?:[^:]{1,2000}:\/+)({web_domain}[^\/:\s]{1,2000})""",
    """\Wurl="(?:-|\w+:\/+[^\/]{1,2000})({uri_path}\/[^?\s]{1,2000})""",
    """\Wurl="(-|([^?]{1,2000}({uri_query}\?[^\s"]{1,2000})))""",
  ]


}
```