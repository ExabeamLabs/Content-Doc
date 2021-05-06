#### Parser Content
```Java
{
Name = forcepoint-web-activity
  Product = Websense Secure Gateway
  DataType = "web-activity"
  Conditions = [ """CEF:""", """|FORCEPOINT|""", """|HTTP_URL-Logged|""" ]
  Fields = ${ForcepointParserTemplates.forcepoint-template.Fields} [
    """\Wmsg=(-|({full_url}(({protocol}[^:\\\/\s,"]+):[\\\/]+)?(({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})|({web_domain}[^\\\/\s:,"]+))?(:({dest_port}\d+))?({uri_path}\/[^\s\?"]*)?({uri_query}\?[^"\s]*)?))"""
    ]
}
forcepoint-template = {
  Vendor = Forcepoint
  Product = Forcepoint
  Lms = ArcSight
  TimeFormat = "epoch"
  Fields=[
    """CEF:\s+\d+\|([^\|]+\|){4}({activity}[^\|]+)""",
    """ahost=\s*({host}.+?)(\s\w+=)""",
    """\Wrt=({time}\d+)""",
    """src=\s*({src_ip}[A-Za-z\d.:]+)""".
    """dhost=\s*({dest_host}.+?)(\s\w+=)""",
    """dst=\s*({dest_ip}.+?)(\s\w+=)""",
    """amac=\s*({mac}.+?)(\s\w+=)""",
    """dvc=\s*({src_host}.+?)(\s\w+=)""",
    """app=\s*({protocol}.+?)(\s\w+=)""",
    """\Win=({bytes_in}\d+)""",
    """\Wout=({bytes_out}\d+)""",
    """\Wspt=({src_port}\d+)""",
    """\Wdpt=({dest_port}\d+)""",
    """\sdeviceInboundInterface=({src_interface}.+?)\s*\w+=""",
    """\sdeviceOutboundInterface=({dest_interface}.+?)\s*\w+=""",
    """\sproto=({protocol}.+?)\s*\w+=""",
    ]

```