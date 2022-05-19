#### Parser Content
```Java
{
Name = cef-cisco-ise-nac-logon-1
  Vendor = Cisco
  Product = Cisco ISE
  Lms = Direct
  DataType = "nac-logon"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Cisco ISE|""", """|TACACS+ Accounting START|""", """CISE_TACACS_Accounting""", """ dvc=""" ]
  Fields = [
    """\srt=({time}\d{1,100})""",
    """\sahost=({host}[\w.-]{1,2000})\s""",
    """({event_name}CISE_TACACS_Accounting)""",
    """\|Cisco ISE\|[^\|]{0,2000}\|({event_code}\d{1,100})""",
    """\sdvchost=({dest_host}[\w.-]{1,2000})\s""",
    """\sdvc=({dest_ip}[A-Fa-f\d.:]{1,2000})\s""",
    """\samac=({src_mac}[\w-]{1,2000})\s""",
    """({auth_type}TACACS\+ Accounting)"""
  ]
  DupFields = [ "host->auth_server" ]


}
```