#### Parser Content
```Java
{
Name = checkpoint-vpn-logout
  Vendor = Check Point Software Technologies
  Product = Next Generation Firewall
  Lms = Direct
  DataType = "vpn-logout"
  TimeFormat = "epoch_sec"
  Conditions = [ """CheckPoint""", """product:""", """action:"Log Out"""", """vpn_""" ]
  Fields = [
    """\W({host}[\w\-.]+) CheckPoint""",
    """\Wtime:"({time}\d+)""",
    """\Wdomain_name:"({domain}[^"]+?)\s*"""",
    """\Wtermination_reason:"({failure_reason}[^"]+?)\s*"""",
    """\Wsrc:"({src_ip}[A-Fa-f:\d.]+)""",
    """\Waction:"({action}[^"]+)""",
    """\Wuser:"({user_lastname}[^,]+),\s*({user_firstname}[\w\s]+\S)\s*\(({account}.+?)\)""",
    """\Wuser:"({user_firstname}[\w\s]+[^\s,])\s+({user_lastname}[^\s,]+)\s*\(({account}.+?)\)""",
    """\Wifdir:"({direction}[^"]+)""",
    """\suser_dn:"+({user_ou}[^"]+)""",
    """\W(user|src_user_name|dst_user_name):"+.+?\(({user}[^)]+)\)"""
  ]
  DupFields = [ "action->event_name" ]
}
```