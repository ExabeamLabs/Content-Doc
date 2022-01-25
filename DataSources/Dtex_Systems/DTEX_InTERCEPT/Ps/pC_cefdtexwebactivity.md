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
    """\WDevice_Name =(({domain}[^\\]{1,2000})\\+)?({host}[^\\\s]{1,2000})""",
    """"OsPlatform":\s{0,100}"({os}[^"]{1,2000})""",
    """"ContentType":\s{0,100}"({mime}[^"]{1,2000})""",
    """"Referrer":\s{0,100}"({referrer}[^"]{1,2000})""",
    """Network_Remote_Port=({dest_port}\d{1,100})""",
    """Website_Protocol=({protocol}[^\s"]{1,2000})""",
    """Website_Query=({full_url}[^\s"]{1,2000})""",
    """Website_Query=(?:-|\w+:\/+[^\/]{1,2000})({uri_path}\/[^?\s]{1,2000})""",
    """Website_Query=(?:-|(?=(?)(?:[^?]{1,2000}({uri_query}\?[^\s"]{1,2000}))))""",
    """Website_Query=(?:[^:]{1,2000}:\/+)({web_domain}[^\/:\s]{1,2000})""",
    """\WUser_Name =(({domain}[^\\]{1,2000})\\+)?({user}[^\\\s]{1,2000})\s""",
    """([^\|]{0,2000}\|){5}({action}[^\|]{1,2000})""",
  ]
  DupFields = [ "host->src_host" ]


}
```