#### Parser Content
```Java
{
Name = cef-cisco-ise-nac-failed-logon
  Vendor = Cisco
  Product = Cisco ISE
  Lms = Direct
  DataType = "nac-failed-logon"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Cisco ISE|""", """|Authentication failed|""", """Access and Identity Management""", """ app=Tacacs """ ]
  Fields = [
    """\srt=({time}\d{1,100})""",
    """\sahost=({host}[\w.-]{1,2000})\s""",
    """({event_name}User authentication failed)""",
    """\|Cisco ISE\|[^\|]{0,2000}\|({event_code}\d{1,100})""",
    """\sdvchost=({dest_host}[\w.-]{1,2000})\s""",
    """\sdst=({dest_ip}[A-Fa-f\d.:]{1,2000})\s""",
    """\sshost=({src_host}[\w.-]{1,2000})\s""",
    """\ssrc=({src_ip}[A-Fa-f\d.:]{1,2000})\s""",
    """\samac=({src_mac}[\w-]{1,2000})\s""",
    """\ssuser=(({user_email}[^\s@]{1,2000}@[^\s@]{1,2000})|({user}[^\s\(\[]{1,2000}))"""
  ]
  DupFields = [ "host->auth_server" ]


}
```