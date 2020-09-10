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
    """exabeam_host=({host}[^\s]+)""",
    """date=({time}\d\d\d\d-\d\d-\d\d time=\d\d:\d\d:\d\d)""",
    """\slevel="*({severity}[^\s"]*)"*""",
    """\sdevname="*({host}[^\s"]*)"*""",
    """\saction="*({action}[^\s"]*)"*""",
    """\sdstip=({dest_ip}[a-fA-F\d.:]+)""",
    """\ssrcip=({src_ip}[a-fA-F\d.:]+)""",
    """\ssrcintf="?({src_interface}.+?)"?\s+(\w+=|$)""",
    """\ssentbyte=({bytes_out}\d+)""",
    """\srcvdbyte=({bytes_in}\d+)""",
    """\sproto=({protocol}[^\s]*)""",
    """\sdstintf="?({dest_interface}.+?)"?\s+(\w+=|$)""",
    """\sdstcountry="?({dest_country}.+?)"?\s+(\w+=|$)""",
    """\ssrcport=({src_port}\d+)""",
    """\sdstport=({dest_port}\d+)""",
    """\ssrccountry="?({src_country}.+?)"?\s+(\w+=|$)""",
    """\suser="?({user}.+?)"?\s+(\w+=|$)""",
    """\stransport=({src_translated_port}d+)""",
    """\stransip=({src_translated_ip}[a-fA-F\d.:]+)""",
    """\smsg="*({additional_info}[^\s"]*)"*""",
    """\slogdesc="*({event_name}[^\s"]*)"*""",
    """\stranport=({src_translated_port}\d+)""",
    """\stranip=({dest_translated_ip}[a-fA-F\d.:]+)""",
    """\ssrcname="*({src_host}[^\s"]*)"*"""
  ]
}
```