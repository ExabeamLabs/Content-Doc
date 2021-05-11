#### Parser Content
```Java
{
Name = cef-attivo-network-connection
  Vendor = Attivo
  Product = BOTsink
  Lms = ArcSight
  DataType = "network-connection"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Attivo|BOTsink|""", """dIPDomain="""]
  Fields = [
    """rt=({time}\d{1,100})""",
    """\d\d:\d\d:\d\d\s({host}[^\s]*)\s""",
    """dvc=({host}[A-Fa-f:\d.]+)""",
    """dst=({dest_ip}[A-Fa-f:\d.]+)""",
    """src=({src_ip}[A-Fa-f:\d.]+)""",
    """smac=({src_mac}(\w{2}:){5}\w{2})""",
    """(dpt|dst_port_list)=({dest_port}\d{1,100})""",
    """dIPDomain=({domain}[^\s]+)""",
    """spt=({src_port}\d{1,100})""",
    """shost=({src_host}[\w\-.]+)""",
    """dhost=({dest_host}[\w\-.]+)""",
    """Interface\\?=({src_interface}[^\s]+)""",
    """msg=\s{0,100}({rule}.+?)\s{1,100}(\w+=|$)""",
    """({direction}Inbound)""",
    """({protocol}RDP|TCP|tcp)""",
    """CEF:([^\|]*\|){5}\s{0,100}({activity}[^\|]*?)\s{0,100}\|""",
   ]
}
```