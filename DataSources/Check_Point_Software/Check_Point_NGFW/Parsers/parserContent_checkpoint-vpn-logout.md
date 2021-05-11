#### Parser Content
```Java
{
Name = checkpoint-vpn-logout
  Vendor = Check Point Software
  Product = Check Point NGFW
  Lms = Direct
  DataType = "vpn-logout"
  TimeFormat = "epoch_sec"
  Conditions = [ """CheckPoint""", """product:""", """action:"Log Out"""", """vpn_""" ]
  Fields = [
    """\W({host}[\w\-.]+) CheckPoint""",
    """\Wtime:"({time}\d{1,100})""",
    """\Wdomain_name:"({domain}[^"]+?)\s{0,100}"""",
    """\Wtermination_reason:"({failure_reason}[^"]+?)\s{0,100}"""",
    """\Wsrc:"({src_ip}[A-Fa-f:\d.]+)""",
    """\Waction:"({action}[^"]+)""",
    """\Wuser:"({user_lastname}[^,]+),\s{0,100}({user_firstname}[\w\s]+\S)\s{0,100}\(({account}.+?)\)""",
    """\Wuser:"({user_firstname}[\w\s]+[^\s,])\s{1,100}({user_lastname}[^\s,]+)\s{0,100}\(({account}.+?)\)""",
    """\Wifdir:"({direction}[^"]+)""",
    """\suser_dn:"{1,20}({user_ou}[^"]+)""",
    """\W(user|src_user_name|dst_user_name):"{1,20}.+?\(({user}[^)]+)\)"""
  ]
  DupFields = [ "action->event_name" ]
}
```