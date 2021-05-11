#### Parser Content
```Java
{
Name = cef-dtex-web-activity
  Vendor = Dtex Systems
  Product = DTEX InTERCEPT
  Lms = ArcSight
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ "CEF:", """|Dtex|""", """|NetworkActivity|WebPageAccessed|""" ]
  Fields = [
    """\Wstart=({time}\d{1,100})""",
    """\WDevice_Name=(({domain}[^\\]+)\\+)?({host}[^\\\s]+)""",
    """"OsPlatform":\s{0,100}"({os}[^"]+)""",
    """"ContentType":\s{0,100}"({mime}[^"]+)""",
    """"Referrer":\s{0,100}"({referrer}[^"]+)""",
    """Network_Remote_Port=({dest_port}\d{1,100})""",
    """Website_Protocol=({protocol}[^\s"]+)""",
    """Website_Query=({full_url}[^\s"]+)""",
    """Website_Query=(?:-|\w+:\/+[^\/]+)({uri_path}\/[^?\s]+)""",
    """Website_Query=(?:-|(?=(?)(?:[^?]+({uri_query}\?[^\s"]+))))""",
    """Website_Query=(?:[^:]+:\/+)({web_domain}[^\/:\s]+)""",
    """Website_Query=(.*?)({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^\.\s\/:]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+(\s|\/|$))[^\s\/]+)""",
    """\WUser_Name=(({domain}[^\\]+)\\+)?({user}[^\\\s]+)\s""",
    """([^\|]*\|){5}({action}[^\|]+)""",
  ]
  DupFields = [ "host->src_host" ]
}
```