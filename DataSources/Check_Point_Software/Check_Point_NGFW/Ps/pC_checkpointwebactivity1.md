#### Parser Content
```Java
{
Name = checkpoint-web-activity-1
  Vendor = Check Point Software
  Product = Check Point NGFW
  Lms = Direct
  TimeFormat = "epoch"
  DataType = "web-activity"
  Conditions = [ """|loguid=""", """|origin=""", """|product=""", """product=URL Filtering""" ]
  Fields = [
    """time=({time}\d{1,100})\|""",
    """hostname=({host}[^|]{1,2000})\|""",
    """app_category=({category}[^|]{1,2000})\|""",
    """appi_name=({app}[^|]{1,2000})\|""",
    """layer_uuid=({uuid}[^|]{1,2000})\|""",
    """rule_action=({action}[^|]{1,2000})\|""",
    """\|action=({action}[^\|]{1,2000})""",
    """rule_name=({rule_name}[^\|]{1,2000})\s{0,100}\|""",
    """origin=({origin_ip}[^|]{1,2000})\|""",
    """dst=({dest_ip}[^|]{1,2000})\|""",
    """method=({method}[^|]{1,2000})\|""",
    """\|resource=((https|http)?:\/+)({web_domain}([^:\|\/]{1,2000}))"""
    """service=({dest_port}[^|]{1,2000})\|""",
    """service_id=({protocol}[^|]{1,2000})\|""",
    """protocol=({protocol}[^\|]{1,2000})""",
    """src=({src_ip}[^|]{1,2000})\|""",
    """ifdir=({direction}[^|]{1,2000})\|""",
    """ifname=({src_interface}[^|]{1,2000})\|""",
    """\|bytes=({bytes}\d{1,100})""",
    """\|server_inbound_bytes=({bytes_in}\d{1,100})""",
    """\|server_outbound_bytes=({bytes_out}\d{1,100})""",
    """(U|u)ser=(-|({user_fullname}[^\(]{1,2000})\s{1,100}\(({user}[^\)]{1,2000}))""",
  ]


}
```