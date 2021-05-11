#### Parser Content
```Java
{
Name = checkpoint-vpn-authentication
  Vendor = Check Point Software
  Product = Check Point NGFW
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  DataType = "vpn-login"
  Conditions = [ """ProductName="Connectra""", """ProductFamily="Network"""", """status=""", """vpn_category=""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\S+\s({host}\d{1,100}.\d{1,100}.\d{1,100}.\d{1,100})\s""",
    """src="({src_ip}\d{1,100}.\d{1,100}.\d{1,100}.\d{1,100})""",
    """dst="({dest_ip}\d{1,100}.\d{1,100}.\d{1,100}.\d{1,100})""",
    """proto="({protocol}[^"]+)""",
    """sport_svc="({src_port}[^"]+)""",
    """svc="({dest_port}[^"]+)""",
    """tunnel_protocol="{1,20}({tunnel_protocol}[^"]+)""",
    """\Wreason="{1,20}({failure_reason}.+?)\s{0,100}"{1,20} latitude=""",
    """\WUser="{1,20}(({user_fullname}[^\(]+)\s\()?(({user_email}[^@"]+@[^"]+)|({user}[^"\)]+))\)?"{1,20} auth_method="""
          
    ]
}
```