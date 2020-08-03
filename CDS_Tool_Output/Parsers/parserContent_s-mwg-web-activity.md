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
    """\Wdatetime="\[({time}[^\[\]]+)""",
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """({host}[\w\-\.]+)\s*mwg:""",
    """\Wuser="({user}[^"]+)""",
    """\Wsrc="({src_ip}[a-fA-F:\d\.]+)""",
    """\Wdest="({dest_ip}[a-fA-F:\d\.]+)""",
    """\Wstatus="({result_code}\d+)""",
    """\Wrisk="({risk_level}[^"]+)""",
    """\Whttp_protocol="({protocol}[^"]+)""",
    """\Whttp_method="({method}[^"]+)""",
    """\Wcategory="({category}[^"]+)""",
    """\Whttp_content_type="({mime}[^"]+)""",
    """\Whttp_user_agent="({user_agent}[^"]+)""",
    """\Whttp_user_agent="({browser}[\w\-]+)\/[\d\._]+""",
    """\Whttp_user_agent="({browser}[^\/;]+).+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
    """\Wvirus_names="(|({ransomware_name}[^"]+))""",
    """\Waction="({action}[^"]+)""",
    """\Wblock_reason="({failure_reason}[^"]+)"""",
    """\Wreferrer="({referrer}[^"]+)""",
    """\Wdomain="(.*?)({top_domain}(?!(?:\d+\.){3}\d+)[^\.\s]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+(\"|\/))[^"\/]+)""",
    """\Wurl="({full_url}[^"]+)""",
    """\Wurl="(\w+:\/+)?({web_domain}[^\/]+)({uri_path}[^"]+)""",
    """\Wurl="(\w+:\/+)?[^\|\/:]+(:\d+)?[^|?]+({uri_query}\?[^\s"]+)""",
    """\Whttp_port="({dest_port}\d+)""",
    """\Wbytes_to_client="({bytes_in}\d+)""",
    """\Wbytes_from_client="({bytes_out}\d+)""",
  ]
}
```