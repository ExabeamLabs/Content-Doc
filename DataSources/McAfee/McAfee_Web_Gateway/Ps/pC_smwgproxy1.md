#### Parser Content
```Java
{
Name = s-mwg-proxy-1
  Vendor = McAfee
  Product = McAfee Web Gateway
  Lms = Direct
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """mwg: """, """status="""", """srcip="""", """mtd="""", """urlp="""", """ua="""", """cache="""" ]
  Fields = [
    """mwg:\s({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """dhost="(-|({dest_host}[^"]{1,2000}))""",
    """status="({result_code}\d{1,100})""",
    """srcip="({src_ip}[a-fA-F\d:.]{1,2000})"""",
    """user="(-|({user}[^"]{1,2000}))"""",
    """dstip="(-|({dest_ip}[a-fA-F\d:.]{1,2000}))"""",
    """srcp="(-|({src_port}\d{1,100}))"""",
    """urlp="(-|({dest_port}\d{1,100}))""",
    """proto="(-|({protocol}[^"]{1,2000}))"""",
    """\smtd="(-|({method}[^"]{1,2000}))"""",
    """urlc="(-|({categories}[^"]{1,2000}))"""",
    """urlc="(-|({category}[^",]{1,2000}))""",
    """\smt="(-|({mime}[^"]{1,2000}))"""",
    """app="(-|({app}[^"]{1,2000}))"""",
    """bytes="(-|({bytes_in}\d{1,100})\/({bytes_out}\d{1,100})\/({bytes_in_post}\d{1,100})\/({bytes_in_get}\d{1,100}))"""",
    """\sua="(_|({user_agent}[^"]{1,2000}))"""",
    """rule="(-|({proxy_action}[^"]{1,2000}))"""",
    """\surl="(-|({full_url}[^"]{1,2000}))"""",
    """\surl="(?:[^:]{1,2000}:\/+)((\d{1,3}\.){3}\d{1,3}|({web_domain}[^\/:\s"]{1,2000}))""",
    """\surl="(-|\w+:\/+[^\/]{1,2000})({uri_path}\/[^?\s"]{1,2000})({uri_query}\?[^\s"]{1,2000})?""", 
    """usrName ="(-|({user}[^"]{1,2000}))""""
  ]


}
```