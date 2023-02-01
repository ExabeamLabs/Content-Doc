#### Parser Content
```Java
{
Name = fortinet-vpn-connection
  Vendor = Fortinet
  Product = FortiGate
  Lms = Direct
  DataType = "vpn-connection"
  TimeFormat = "epoch_sec"
  Conditions = [ """|Fortinet|Fortigate|""", """|event:vpn success|""", """FTNTFGTeventtime=""", """FTNTFGTsubtype=vpn""" ]
  Fields = [
    """FTNTFGTeventtime=({time}\d{1,19})""",
    """\s\d\d:\d\d:\d\d\s({host}[\w\-\.]{1,2000})""",
    """\ssrc=({src_ip}[a-fA-F\d\.]{1,2000})""",
    """\sspt=({src_port}\d{1,5})""",
    """\sdst=({dest_ip}[a-fA-F\d\.]{1,2000})""",
    """\sdpt=({dest_port}\d{1,5})""",
    """\sact=({action}[^=]{1,2000}?)\s\w+=""",
    """FTNTFGTresult=({result}[^"]{1,2000})$""",
    """\|Fortinet\|Fortigate\|([^|]{1,2000}\|){2}({event_name}[^|]{1,2000})\|""",
    """FTNTFGTdir=({direction}[^=]{1,2000}?)\s\w+=""",
    """\smsg=({additional_info}[^=]{1,2000}?)\s\w+=""",
    """outcome=({outcome}[^=]{1,2000}?)\s\w+="""
  ]


}
```