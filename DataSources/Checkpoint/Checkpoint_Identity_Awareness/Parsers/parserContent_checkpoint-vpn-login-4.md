#### Parser Content
```Java
{
Name = checkpoint-vpn-login-4
  Vendor = Checkpoint
  Product = Checkpoint Identity Awareness
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "dMMMyyyy H:mm:ss"
  Conditions = [ """Product=Identity Awareness""" , """Login""", """Source=""", """User="""]
  Fields = [
    """src_user_group=(-|({user_group}[^\|]+))\|""",
    """auth_method=(-|({auth_method}[^\|]+))\|""",
    """auth_status=(-|({action}Successful|Failed))""",
    """\s+({time}\d{1,2}\w+\d\d\d\s\d{1,2}:\d{1,2}:\d{1,2})\|""",
    """Originip=({host}[^\|]+)\|""",
    """Origin=({host}[^\|]+)\|""",
    """Action=(-|({activity}[^\|]+))\|""",
    """SIP=({src_ip}[^\|]+)\|""",
    """SPort=({src_port}\d+)""",
    """DPort=({dest_port}\d+)""",
    """Destination=(-|({dest_host}[^\|]+))\|""",
    """DIP=(-|({dest_ip}[^\|]+))\|""",
    """Protocol=(-|({protocol}[^\|]+))\|""",
    """IFDirection=(-|({direction}[^\|]+))\|""",
    """Reason=(-|({reason}[^\|]+))\|""",
    """(U|u)ser=(-|({user_fullname}[^\(]+)\s+\(({user}[^\)]+))""",
    """domain_name=(-|({domain}[^\|]+))\|""",
    """termination_reason=(-|({failure_reason}[^\|]+))\|""",
    """duration=(-|({session_duration}[^\|]+))\|""",
    """description=(-|({additional_info}[^\|]+))\|""",
  ]
}
```