#### Parser Content
```Java
{
Name = openvpn-vpn-end-1
  DataType = "vpn-end"
  Conditions = [ """id=ArrayOS""", """TCP tunnel""", """has been terminated for""", """type=vpn""" ]

openvpn-events = {
  Vendor = SSL Open VPN
  Product = SSL Open VPN
  Lms = Direct
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\Wtime="({time}\d\d\d\d-\d{1,100}-\d{1,100} \d\d:\d\d:\d\d)""",
    """\Wuser=({user}[^\s]{1,2000})""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wdst=(0\.0\.0\.0|({dest_ip}[A-Fa-f:\d.]{1,2000}))""",
    """\Wsport=({src_port}\d{1,100})""",
    """\Wdport=({dest_port}\d{1,100})""",
    """\Wdstname=({dest_host}[\w\-.]{1,2000})""",
    """\Wgroup info:\s{0,100}\(({group_info}[^\)]{1,2000})""",
    """\Wlogin method:?\s{0,100}\(({login_method}[^\)]{1,2000})""",
    """\Wreason\s{0,100}\(({failure_reason}[^\)]{1,2000})""",
    """\Wsession id\s{1,100}({session_id}[^,]{1,2000})""",
    """\Wduration\s{1,100}({duration}[^.]{1,2000})""",
    """\WTCP tunnel\(({src_translated_ip}[A-Fa-f:\d.]{1,2000})\)""",
    """\Wclientip\(({src_translated_ip}[A-Fa-f:\d.]{1,2000})\)""",
  ]
  DupFields = ["user->account"
}
```