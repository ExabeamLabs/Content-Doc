#### Parser Content
```Java
{
Name = checkpoint-web-activity-1
  Vendor = Check Point
  Lms = Direct
  TimeFormat = "epoch"
  DataType = "web-activity"
  Conditions = [ """|loguid=""", """|origin=""", """|product=""", """product=URL Filtering""" ]
  Fields = [
    """time=({time}\d+)\|""",
    """hostname=({host}[^|]+)\|""",
    """app_category=({category}[^|]+)\|""",
    """appi_name=({app}[^|]+)\|""",
    """layer_uuid=({uuid}[^|]+)\|""",
    """rule_action=({action}[^|]+)\|""",
    """\|action=({action}[^\|]+)""",
    """rule_name=({rule_name}[^\|]+)\s*\|""",
    """origin=({origin_ip}[^|]+)\|""",
    """client_type_os=({os}[^|]+)\|""",
    """dst=({dest_ip}[^|]+)\|""",
    """method=({method}[^|]+)\|""",
    """\|resource=((https|http)?:\/+)({web_domain}([^:\|\/]+\.)?({top_domain}[^\.\/]+\.[^:\|\/\d]+))"""
    """service=({dest_port}[^|]+)\|""",
    """service_id=({protocol}[^|]+)\|""",
    """protocol=({protocol}[^\|]+)""",
    """src=({src_ip}[^|]+)\|""",
    """web_client_type=({browser}[^|]+)\|""",
    """ifdir=({direction}[^|]+)\|""",
    """ifname=({src_interface}[^|]+)\|""",
    """\|bytes=({bytes}\d+)""",
    """\|server_inbound_bytes=({bytes_in}\d+)""",
    """\|server_outbound_bytes=({bytes_out}\d+)""",
    """(U|u)ser=(-|({user_fullname}[^\(]+)\s+\(({user}[^\)]+))""",
  ]
}
```