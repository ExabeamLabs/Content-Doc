#### Parser Content
```Java
{
Name = forcepoint-web-activity
  Product = Websense Secure Gateway
  DataType = "web-activity"
  Conditions = [ """CEF:""", """|FORCEPOINT|""", """|HTTP_URL-Logged|""" ]
  Fields = ${ForcepointParserTemplates.forcepoint-template.Fields} [
    """\Wmsg=(-|({full_url}(({protocol}[^:\\\/\s,"]{1,2000}):[\\\/]{1,2000})?(({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})|({web_domain}[^\\\/\s:,"]{1,2000}))?(:({dest_port}\d{1,100}))?({uri_path}\/[^\s\?"]{0,2000})?({uri_query}\?[^"\s]{0,2000})?))"""
    ]
}
forcepoint-template = {
  Vendor = Forcepoint
  Product = Forcepoint
  Lms = ArcSight
  TimeFormat = "epoch"
  Fields=[
    """CEF:\s{1,100}\d{1,100}\|([^\|]{1,2000}\|){4}({activity}[^\|]{1,2000})""",
    """ahost=\s{0,100}({host}.+?)(\s\w+=)""",
    """\Wrt=({time}\d{1,100})""",
    """src=\s{0,100}({src_ip}[A-Za-z\d.:]{1,2000})""".
    """dhost=\s{0,100}({dest_host}.+?)(\s\w+=)""",
    """dst=\s{0,100}({dest_ip}.+?)(\s\w+=)""",
    """amac=\s{0,100}({mac}.+?)(\s\w+=)""",
    """dvc=\s{0,100}({src_host}.+?)(\s\w+=)""",
    """app=\s{0,100}({protocol}.+?)(\s\w+=)""",
    """\Win=({bytes_in}\d{1,100})""",
    """\Wout=({bytes_out}\d{1,100})""",
    """\Wspt=({src_port}\d{1,100})""",
    """\Wdpt=({dest_port}\d{1,100})""",
    """\sdeviceInboundInterface=({src_interface}.+?)\s{0,100}\w+=""",
    """\sdeviceOutboundInterface=({dest_interface}.+?)\s{0,100}\w+=""",
    """\sproto=({protocol}.+?)\s{0,100}\w+=""",
    ]

```