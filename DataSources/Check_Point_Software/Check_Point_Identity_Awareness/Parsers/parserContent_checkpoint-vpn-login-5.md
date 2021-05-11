#### Parser Content
```Java
{
Name = checkpoint-vpn-login-5
  Vendor = Check Point Software
  Product = Check Point Identity Awareness
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "epoch"
  Conditions = [ """product=Identity Awareness""" , """|auth_status=Successful Login|""" ]
  Fields = [
    """"time=({time}\d{1,100})""",
    """\|hostname=({host}.+?)\s{0,100}\|""",
    """(U|u)ser=(-|({user_fullname}[^\(]+)\s{1,100}\(({user}[^\)]+))""",
    """\|src_user_group=({user_group}.+?)\s{0,100}\|""",
    """\|src_machine_name=({src_host}[^\|]+)""",
    """\|src=({src_ip}[^\|]+)""",
    """\|endpoint_ip=({dest_ip}[^\|]+)""",
    """\|ifdir=({direction}[^\|]+)""",
    """\|logid=({log_id}[^\|]+)""",
    """\|loguid=({log_uid}[^\|]+)""",
    """\|origin=({origin_ip}[^\|]+)""",
    """\|originsicname=({user_ou}[^\|]+)""",
    """\|auth_method=({auth_method}[^\|]+)""",
    """\|auth_status=({outcome}[^\|]+)""",
    """\|domain_name=({domain}[^\|]+)""",
    """({action}Successful)"""
  ]
}
```