#### Parser Content
```Java
{
Name = checkpoint-vpn-logout-2
  Vendor = Check Point Software
  Product = Check Point Identity Awareness
  Lms = Direct
  DataType = "vpn-logout"
  TimeFormat = "epoch"
  Conditions = [ """product=Identity Awareness|action=Log Out""" ]
  Fields = [
    """time=({time}\d{1,100})""",
    """Origin=({origin_ip}[^\|]+)\|""",
    """(U|u)ser=(-|({user_fullname}[^\(]+)\s{1,100}\(({user}[^\)]+))""",
    """domain_name=(-|({domain}[^\|]+))\|""",
    """termination_reason=(-|({failure_reason}[^\|]+))\|""",
    """duration=(-|({session_duration}[^\|]+))\|""",
    """description=(-|({additional_info}[^\|]+))\|""",
    """\|hostname=({host}.+?)\s{0,100}\|""",
    """\|src_user_group=({user_group}.+?)\s{0,100}\|""",
    """\|src=({src_ip}[^\|]+)""",
    """\|ifdir=({direction}[^\|]+)""",
    """\|logid=({log_id}[^\|]+)""",
    """\|loguid=({log_uid}[^\|]+)""",
    """\|origin=({origin_ip}[^\|]+)""",
    """\|originsicname=({user_ou}[^\|]+)""",
  ]
}
```