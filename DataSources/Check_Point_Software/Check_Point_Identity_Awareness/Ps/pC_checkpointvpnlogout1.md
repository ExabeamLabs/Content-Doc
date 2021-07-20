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
    """src_user_group=(-|({user_group}[^\|]{1,2000}))\|""",
    """auth_method=(-|({auth_method}[^\|]{1,2000}))\|""",
    """\s{1,100}({time}\d{1,2}\w+\d\d\d\s\d{1,2}:\d{1,2}:\d{1,2})\|""",
    """Originip=({host}[^\|]{1,2000})\|""",
    """Origin=({host}[^\|]{1,2000})\|""",
    """Action=(-|({activity}[^\|]{1,2000}))\|""",
    """SIP=({src_ip}[^\|]{1,2000})\|""",
    """SPort=({src_port}\d{1,100})""",
    """DPort=({dest_port}\d{1,100})""",
    """Destination=(-|({dest_host}[^\|]{1,2000}))\|""",
    """DIP=(-|({dest_ip}[^\|]{1,2000}))\|""",
    """Protocol=(-|({protocol}[^\|]{1,2000}))\|""",
    """IFDirection=(-|({direction}[^\|]{1,2000}))\|""",
    """Reason=(-|({reason}[^\|]{1,2000}))\|""",
    """(U|u)ser=(-|({user_fullname}[^\(]{1,2000})\s{1,100}\(({user}[^\)]{1,2000}))""",
    """domain_name=(-|({domain}[^\|]{1,2000}))\|""",
    """termination_reason=(-|({failure_reason}[^\|]{1,2000}))\|""",
    """duration=(-|({session_duration}[^\|]{1,2000}))\|""",
    """description=(-|({additional_info}[^\|]{1,2000}))\|""",
  ]
}
```