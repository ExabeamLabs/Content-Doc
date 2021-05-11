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
    """devname="{0,20}({host}[\w\-.]+)""",
    """date=({time}\d\d\d\d-\d\d-\d\d time=\d\d:\d\d:\d\d([+-]\d\d:\d\d)?)""",
    """\slevel="{0,20}({severity}[^\s"]*)"{0,20}""",
    """\smsg="{0,20}({additional_info}[^"]*)"{0,20}""",
    """\saction="{0,20}({action}[^\s"]*)"{0,20}""",
    """\sremip=({dest_ip}[a-fA-F\d.:]+)""",
    """\slocip=({src_ip}[a-fA-F\d.:]+)""",
    """\sremport=({dest_port}\d{1,100})""",
    """\slocport=({src_port}\d{1,100})""",
    """\suser="(?:N\/A|({user}[^\s@"]+))"""",
    """\suser="(?:N\/A|({user_email}[^\s@"]+@[^\s@"]+))"""",
    """\sstatus="{0,20}({outcome}[^\s"]*)"{0,20}""",
    """\sdir="{0,20}({direction}[^\s"]*)"{0,20}"""
  ]
}
```