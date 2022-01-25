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
    """(U|u)ser=(-|({user_fullname}[^\(]{1,2000})\s{1,100}\(({user}[^\)]{1,2000}))""",
    """\|src_user_group=({user_group}.+?)\s{0,100}\|""",
    """\|src_machine_name=({src_host}[^\|]{1,2000})""",
    """\|src=({src_ip}[^\|]{1,2000})""",
    """\|endpoint_ip=({dest_ip}[^\|]{1,2000})""",
    """\|ifdir=({direction}[^\|]{1,2000})""",
    """\|logid=({log_id}[^\|]{1,2000})""",
    """\|loguid=({log_uid}[^\|]{1,2000})""",
    """\|origin=({origin_ip}[^\|]{1,2000})""",
    """\|originsicname=({user_ou}[^\|]{1,2000})""",
    """\|auth_method=({auth_method}[^\|]{1,2000})""",
    """\|auth_status=({outcome}[^\|]{1,2000})""",
    """\|domain_name=({domain}[^\|]{1,2000})""",
    """({action}Successful)"""
  ]


}
```