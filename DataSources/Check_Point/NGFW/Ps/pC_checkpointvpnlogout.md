#### Parser Content
```Java
{
Name = checkpoint-vpn-logout
  Vendor = Check Point 
  Product = NGFW
  Lms = Direct
  DataType = "vpn-logout"
  TimeFormat = "epoch_sec"
  Conditions = [ """CheckPoint""", """product:""", """action:"Log Out"""", """vpn_""" ]
  Fields = [
    """\W({host}[\w\-.]{1,2000}) CheckPoint""",
    """\Wtime:"({time}\d{1,100})""",
    """\Wdomain_name:"({domain}[^"]{1,2000}?)\s{0,100}"""",
    """\Wtermination_reason:"({failure_reason}[^"]{1,2000}?)\s{0,100}"""",
    """\Wsrc:"({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Waction:"({action}[^"]{1,2000})""",
    """\Wuser:"({user_lastname}[^,]{1,2000}),\s{0,100}({user_firstname}[\w\s]{1,2000}\S)\s{0,100}\(({account}.+?)\)""",
    """\Wuser:"({user_firstname}[\w\s]{1,2000}[^\s,])\s{1,100}({user_lastname}[^\s,]{1,2000})\s{0,100}\(({account}.+?)\)""",
    """\Wifdir:"({direction}[^"]{1,2000})""",
    """\suser_dn:"{1,20}({user_ou}[^"]{1,2000})""",
    """\W(user|src_user_name|dst_user_name):"{1,20}.+?\(({user}[^)]{1,2000})\)"""
  ]
  DupFields = [ "action->event_name" ]


}
```