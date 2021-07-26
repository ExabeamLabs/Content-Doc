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
    """\d\d:\d\d:\d\d\s({host}[^\s]{0,2000})\s""",
    """dvc=({host}[A-Fa-f:\d.]{1,2000})""",
    """dst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """src=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """smac=({src_mac}(\w{2}:){5}\w{2})""",
    """(dpt|dst_port_list)=({dest_port}\d{1,100})""",
    """dIPDomain=({domain}[^\s]{1,2000})""",
    """spt=({src_port}\d{1,100})""",
    """shost=({src_host}[\w\-.]{1,2000})""",
    """dhost=({dest_host}[\w\-.]{1,2000})""",
    """Interface\\?=({src_interface}[^\s]{1,2000})""",
    """msg=\s{0,100}({rule}.+?)\s{1,100}(\w+=|$)""",
    """({direction}Inbound)""",
    """({protocol}RDP|TCP|tcp)""",
    """CEF:([^\|]{0,2000}\|){5}\s{0,100}({activity}[^\|]{0,2000}?)\s{0,100}\|""",
   ]
}
```