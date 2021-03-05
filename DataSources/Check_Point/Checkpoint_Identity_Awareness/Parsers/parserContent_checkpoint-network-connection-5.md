#### Parser Content
```Java
{
Name = checkpoint-network-connection-5
  Vendor = Check Point
  Product = Checkpoint Identity Awareness
  Lms = Direct
  TimeFormat = "epoch"
  DataType = "network-connection"
  Conditions = [ """|loguid=""", """|origin=""", """|product=""" ]
  Fields = [
    """"time=({time}\d+)\|""",
    """hostname=({host}[^|]+)\|""",
    """layer_uuid=({uuid}[^|]+)\|""",
    """rule_action=({action}[^|]+)\|""",
    """action=({action}[^\|]+)""",
    """origin=({origin_ip}[^|]+)\|""",
    """dst=({dest_ip}[^|]+)\|""",
    """service=({dest_port}[^|]+)\|""",
    """service_id=({protocol}[^|]+)\|""",
    """src=({src_ip}[^|]+)\|""",
    """ifdir=({direction}[^|]+)\|""",
    """ifname=({src_interface}[^|]+)\|""",
    """\|logid=({log_id}[^\|]+)""",
    """\|loguid=({log_uid}[^\|]+)""",
    """\|s_port=({src_port}\d+)""",
    """(U|u)ser=(-|({user_fullname}[^\(]+)\s+\(({user}[^\)]+))""",
  ]
}
```