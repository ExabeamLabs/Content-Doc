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
    """Origin=({origin_ip}[^\|]{1,2000})\|""",
    """(U|u)ser=(-|({user_fullname}[^\(]{1,2000})\s{1,100}\(({user}[^\)]{1,2000}))""",
    """domain_name=(-|({domain}[^\|]{1,2000}))\|""",
    """termination_reason=(-|({failure_reason}[^\|]{1,2000}))\|""",
    """duration=(-|({session_duration}[^\|]{1,2000}))\|""",
    """description=(-|({additional_info}[^\|]{1,2000}))\|""",
    """\|hostname=({host}.+?)\s{0,100}\|""",
    """\|src_user_group=({user_group}.+?)\s{0,100}\|""",
    """\|src=({src_ip}[^\|]{1,2000})""",
    """\|ifdir=({direction}[^\|]{1,2000})""",
    """\|logid=({log_id}[^\|]{1,2000})""",
    """\|loguid=({log_uid}[^\|]{1,2000})""",
    """\|origin=({origin_ip}[^\|]{1,2000})""",
    """\|originsicname=({user_ou}[^\|]{1,2000})""",
  ]
}
```