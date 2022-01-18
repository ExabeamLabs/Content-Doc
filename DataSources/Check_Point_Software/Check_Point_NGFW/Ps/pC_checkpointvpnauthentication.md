#### Parser Content
```Java
{
Name = checkpoint-vpn-authentication
  Vendor = Check Point Software
  Product = Check Point NGFW
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  DataType = "vpn-login"
  Conditions = [ """ProductName ="Connectra""", """ProductFamily="Network"""", """status=""", """vpn_category=""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\S+\s({host}\d{1,100}.\d{1,100}.\d{1,100}.\d{1,100})\s""",
    """src="({src_ip}\d{1,100}.\d{1,100}.\d{1,100}.\d{1,100})""",
    """dst="({dest_ip}\d{1,100}.\d{1,100}.\d{1,100}.\d{1,100})""",
    """proto="({protocol}[^"]{1,2000})""",
    """sport_svc="({src_port}[^"]{1,2000})""",
    """svc="({dest_port}[^"]{1,2000})""",
    """tunnel_protocol="{1,20}({tunnel_protocol}[^"]{1,2000})""",
    """\Wreason="{1,20}({failure_reason}.+?)\s{0,100}"{1,20} latitude=""",
    """\WUser="{1,20}(({user_fullname}[^\(]{1,2000})\s\()?(({user_email}[^@"]{1,2000}@[^"]{1,2000})|({user}[^"\)]{1,2000}))\)?"{1,20} auth_method="""
          
    ]


}
```