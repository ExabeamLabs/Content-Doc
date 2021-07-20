#### Parser Content
```Java
{
Name = checkpoint-network-connection-5
  Vendor = Check Point Software
  Product = Check Point Identity Awareness
  Lms = Direct
  TimeFormat = "epoch"
  DataType = "network-connection"
  Conditions = [ """|loguid=""", """|origin=""", """|product=""" ]
  Fields = [
    """"time=({time}\d{1,100})\|""",
    """hostname=({host}[^|]{1,2000})\|""",
    """layer_uuid=({uuid}[^|]{1,2000})\|""",
    """rule_action=({action}[^|]{1,2000})\|""",
    """action=({action}[^\|]{1,2000})""",
    """origin=({origin_ip}[^|]{1,2000})\|""",
    """dst=({dest_ip}[^|]{1,2000})\|""",
    """service=({dest_port}[^|]{1,2000})\|""",
    """service_id=({protocol}[^|]{1,2000})\|""",
    """src=({src_ip}[^|]{1,2000})\|""",
    """ifdir=({direction}[^|]{1,2000})\|""",
    """ifname=({src_interface}[^|]{1,2000})\|""",
    """\|logid=({log_id}[^\|]{1,2000})""",
    """\|loguid=({log_uid}[^\|]{1,2000})""",
    """\|s_port=({src_port}\d{1,100})""",
    """(U|u)ser=(-|({user_fullname}[^\(]{1,2000})\s{1,100}\(({user}[^\)]{1,2000}))""",
  ]
}
```