#### Parser Content
```Java
{
Name = checkpoint-vpn-authentication
  Vendor = Check Point
  Product = Check Point NGFW
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  DataType = "vpn-login"
  Conditions = [ """ProductName="Connectra""", """ProductFamily="Network"""", """status=""", """vpn_category=""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\S+\s({host}\d+.\d+.\d+.\d+)\s""",
    """src="({src_ip}\d+.\d+.\d+.\d+)""",
    """dst="({dest_ip}\d+.\d+.\d+.\d+)""",
    """proto="({protocol}[^"]+)""",
    """sport_svc="({src_port}[^"]+)""",
    """svc="({dest_port}[^"]+)""",
    """tunnel_protocol="+({tunnel_protocol}[^"]+)""",
    """\Wreason="+({failure_reason}.+?)\s*"+ latitude=""",
    """\WUser="+(({user_fullname}[^\(]+)\s\()?(({user_email}[^@"]+@[^"]+)|({user}[^"\)]+))\)?"+ auth_method="""
          
    ]
}
```