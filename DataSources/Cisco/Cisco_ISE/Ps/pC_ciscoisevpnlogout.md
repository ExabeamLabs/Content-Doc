#### Parser Content
```Java
{
Name = cisco-ise-vpn-logout
  Vendor = Cisco
  Product = Cisco ISE
  Lms = Direct
  DataType = "vpn-end"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Cisco ISE|""", """|RADIUS Accounting stop request|""", """ act=Stop """ ]
  Fields = [
    """\srt=({time}\d{1,100})""",
    """\sahost=({host}[\w.-]{1,2000})\s""",
    """\sdvchost=({dest_host}[\w.-]{1,2000})\s""",
    """\sdst=({dest_ip}[A-Fa-f\d.:]{1,2000})\s""",
    """\sshost=({src_host}[\w.-]{1,2000})\s""",
    """\ssrc=({src_ip}[A-Fa-f\d.:]{1,2000})\s""",
    """\samac=({src_mac}[\w-]{1,2000})\s""",
    """\ssuser=(({user_email}[^\s@]{1,2000}@[^\s@]{1,2000})|({user}[^\s\(\[]{1,2000}))""",
    """({event_name}RADIUS Accounting stop request)""",
    """\|Cisco ISE\|[^\|]{0,2000}\|({event_code}\d{1,100})""",	
    """Acct Session Time:\s{0,100}({session_duration}\d{1,100}),""",
    """\scs5=({session_id}[^\s=]{1,2000})""",
    """\sout=({bytes_out}[+-]?\d{1,100})""",
    """\sin=({bytes_in}[+-]?\d{1,100})"""
  ]


}
```