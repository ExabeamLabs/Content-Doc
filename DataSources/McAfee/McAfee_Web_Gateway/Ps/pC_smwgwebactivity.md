#### Parser Content
```Java
{
Name = s-mwg-web-activity
  Vendor = McAfee
  Product = McAfee Web Gateway
  Lms = Splunk
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "dd/MMM/yyyy:HH:mm:ss Z"
  Conditions = [ """mwg:""", """datetime="""", """authentication_method="""" ]
  Fields = [
    """\Wdatetime="\[({time}[^\[\]]{1,2000})""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """({host}[\w\-\.]{1,2000})\s{0,100}mwg:""",
    """\Wuser="({user}[^"]{1,2000})""",
    """\Wsrc="({src_ip}[a-fA-F:\d\.]{1,2000})""",
    """\Wdest="({dest_ip}[a-fA-F:\d\.]{1,2000})""",
    """\Wstatus="({result_code}\d{1,100})""",
    """\Wrisk="({risk_level}[^"]{1,2000})""",
    """\Whttp_protocol="({protocol}[^"]{1,2000})""",
    """\Whttp_method="({method}[^"]{1,2000})""",
    """\Wcategory="({category}[^"]{1,2000})""",
    """\Whttp_content_type="({mime}[^"]{1,2000})""",
    """\Whttp_user_agent="({user_agent}[^"]{1,2000})""",
    """\Wvirus_names="(|({ransomware_name}[^"]{1,2000}))""",
    """\Waction="({action}[^"]{1,2000})""",
    """\Wblock_reason="({failure_reason}[^"]{1,2000})"""",
    """\Wreferrer="({referrer}[^"]{1,2000})""",
    """\Wurl="({full_url}[^"]{1,2000})""",
    """\Wurl="(\w+:\/+)?({web_domain}[^\/]{1,2000})({uri_path}[^"]{1,2000})""",
    """\Wurl="(\w+:\/+)?[^\|\/:]{1,2000}(:\d{1,100})?[^|?]{1,2000}({uri_query}\?[^\s"]{1,2000})""",
    """\Whttp_port="({dest_port}\d{1,100})""",
    """\Wbytes_to_client="({bytes_in}\d{1,100})""",
    """\Wbytes_from_client="({bytes_out}\d{1,100})""",
  ]


}
```