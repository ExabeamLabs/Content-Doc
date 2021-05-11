#### Parser Content
```Java
{
Name = checkpoint-vpn-logout-1
  Vendor = Check Point Software
  Product = Check Point Identity Awareness
  Lms = Direct
  DataType = "vpn-end"
  TimeFormat = "dMMMyyyy H:mm:ss"
  Conditions = [ """Product=Identity Awareness""" , """logout""", """Source=""", """User="""]
  Fields = [
    """src_user_group=(-|({user_group}[^\|]+))\|""",
    """auth_method=(-|({auth_method}[^\|]+))\|""",
    """\s{1,100}({time}\d{1,2}\w+\d\d\d\s\d{1,2}:\d{1,2}:\d{1,2})\|""",
    """Originip=({host}[^\|]+)\|""",
    """Origin=({host}[^\|]+)\|""",
    """Action=(-|({activity}[^\|]+))\|""",
    """SIP=({src_ip}[^\|]+)\|""",
    """SPort=({src_port}\d{1,100})""",
    """DPort=({dest_port}\d{1,100})""",
    """Destination=(-|({dest_host}[^\|]+))\|""",
    """DIP=(-|({dest_ip}[^\|]+))\|""",
    """Protocol=(-|({protocol}[^\|]+))\|""",
    """IFDirection=(-|({direction}[^\|]+))\|""",
    """Reason=(-|({reason}[^\|]+))\|""",
    """(U|u)ser=(-|({user_fullname}[^\(]+)\s{1,100}\(({user}[^\)]+))""",
    """domain_name=(-|({domain}[^\|]+))\|""",
    """termination_reason=(-|({failure_reason}[^\|]+))\|""",
    """duration=(-|({session_duration}[^\|]+))\|""",
    """description=(-|({additional_info}[^\|]+))\|""",
  ]
}
```