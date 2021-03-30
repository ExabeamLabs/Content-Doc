#### Parser Content
```Java
{
Name = fortios-network-connection-1
  Vendor = Fortinet
  Product = Fortinet Enterprise Firewall
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd 'time='HH:mm:ssZ"
  Conditions = [ """type="event"""", """subtype="vpn"""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """devname="*({host}[\w\-.]+)""",
    """date=({time}\d\d\d\d-\d\d-\d\d time=\d\d:\d\d:\d\d([+-]\d\d:\d\d)?)""",
    """\slevel="*({severity}[^\s"]*)"*""",
    """\smsg="*({additional_info}[^"]*)"*""",
    """\saction="*({action}[^\s"]*)"*""",
    """\sremip=({dest_ip}[a-fA-F\d.:]+)""",
    """\slocip=({src_ip}[a-fA-F\d.:]+)""",
    """\sremport=({dest_port}\d+)""",
    """\slocport=({src_port}\d+)""",
    """\suser="(?:N\/A|({user}[^\s@"]+))"""",
    """\suser="(?:N\/A|({user_email}[^\s@"]+@[^\s@"]+))"""",
    """\sstatus="*({outcome}[^\s"]*)"*""",
    """\sdir="*({direction}[^\s"]*)"*"""
  ]
}
```