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
    """exabeam_host=({host}[^\s]{1,2000})""",
    """date=({time}\d\d\d\d-\d\d-\d\d time=\d\d:\d\d:\d\d)""",
    """devname="{0,20}({host}[^"]{1,2000}?)"{0,20}(\s{1,100}\w+=|\s{0,100}$)""",
    """\ssrcip="?({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\suser="{0,20}({user}[^"]{1,2000}?)"{0,20}(\s{1,100}\w+=|\s{0,100}$)""",
    """\slogdesc="({event_name}[^"]{1,2000})""",
    """\smsg="({additional_info}[^"]{1,2000})""",
  ]
}
```