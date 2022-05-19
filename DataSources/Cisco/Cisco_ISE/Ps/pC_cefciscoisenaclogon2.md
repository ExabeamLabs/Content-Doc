#### Parser Content
```Java
{
Name = cef-cisco-ise-nac-logon-2
  Vendor = Cisco
  Product = Cisco ISE
  Lms = Direct
  DataType = "nac-logon"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Cisco ISE|""", """|RADIUS Accounting start request|""", """ dst=""", """act=Start""", """CISE_RADIUS_Accounting""" ]
  Fields = [
    """\srt=({time}\d{1,100})""",
    """\sahost=({host}[\w.-]{1,2000})\s""",
    """({event_name}RADIUS Accounting start request)""",
    """\|Cisco ISE\|[^\|]{0,2000}\|({event_code}\d{1,100})""",
    """\sdvchost=({dest_host}[\w.-]{1,2000})\s""",
    """\sdst=({dest_ip}[A-Fa-f\d.:]{1,2000})\s""",
    """\sshost=({src_host}[\w.-]{1,2000})\s""",
    """\ssrc=({src_ip}[A-Fa-f\d.:]{1,2000})\s""",
    """\samac=({src_mac}[\w-]{1,2000})\s""",
    """\ssuser=(({user_email}[^\s@]{1,2000}@[^\s@]{1,2000})|({user}[^\s\(\[]{1,2000}))""",
    """({auth_type}Radius-Accounting)"""
  ]
  DupFields = [ "host->auth_server" ]


}
```