#### Parser Content
```Java
{
Name = fortinet-0102043039
  Vendor = Fortinet
  Product = Fortinet VPN
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd 'time='HH:mm:ss"
  Conditions = [ """ logid="0102043039" """ ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """date=({time}\d\d\d\d-\d\d-\d\d time=\d\d:\d\d:\d\d)""",
    """devname="*({host}[^"]+?)"*(\s+\w+=|\s*$)""",
    """\ssrcip="?({src_ip}[a-fA-F\d.:]+)""",
    """\suser="*({user}[^"]+?)"*(\s+\w+=|\s*$)""",
    """\slogdesc="({event_name}[^"]+)""",
    """\smsg="({additional_info}[^"]+)""",
  ]
}
```