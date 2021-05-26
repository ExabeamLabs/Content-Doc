#### Parser Content
```Java
{
Name = fortios-network-connection-successful
  Vendor = Fortinet
  Product = Fortinet Enterprise Firewall
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd 'time='HH:mm:ss"
  Conditions = [ " vd=", " devname=", " devid=", " logid=", " level=", "action=accept" ]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """date=({time}\d\d\d\d-\d\d-\d\d time=\d\d:\d\d:\d\d)""",
    """\slevel="{0,20}({severity}[^\s"]{0,2000})"{0,20}""",
    """\sdevname="{0,20}({host}[^\s"]{0,2000})"{0,20}""",
    """\saction="{0,20}({action}[^\s"]{0,2000})"{0,20}""",
    """\sdstip=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\ssrcip=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\ssrcintf="?({src_interface}.+?)"?\s{1,100}(\w+=|$)""",
    """\ssentbyte=({bytes_out}\d{1,100})""",
    """\srcvdbyte=({bytes_in}\d{1,100})""",
    """\sproto=({protocol}[^\s]{0,2000})""",
    """\sdstintf="?({dest_interface}.+?)"?\s{1,100}(\w+=|$)""",
    """\sdstcountry="?({dest_country}.+?)"?\s{1,100}(\w+=|$)""",
    """\ssrcport=({src_port}\d{1,100})""",
    """\sdstport=({dest_port}\d{1,100})""",
    """\ssrccountry="?({src_country}.+?)"?\s{1,100}(\w+=|$)""",
    """\suser="?({user}.+?)"?\s{1,100}(\w+=|$)""",
    """\stransport=({src_translated_port}d+)""",
    """\stransip=({src_translated_ip}[a-fA-F\d.:]{1,2000})""",
    """\smsg="{0,20}({additional_info}[^\s"]{0,2000})"{0,20}""",
    """\slogdesc="{0,20}({event_name}[^\s"]{0,2000})"{0,20}""",
    """\stranport=({src_translated_port}\d{1,100})""",
    """\stranip=({dest_translated_ip}[a-fA-F\d.:]{1,2000})""",
    """\ssrcname="{0,20}({src_host}[^\s"]{0,2000})"{0,20}"""
  ]
}
```