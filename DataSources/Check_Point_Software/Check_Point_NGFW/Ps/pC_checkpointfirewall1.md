#### Parser Content
```Java
{
Name = checkpoint-firewall-1
  DataType = "alert"
  Conditions = [ """|Check Point|VPN-1 & FireWall-1|""" , """layer_name="""]

checkpoint-firewall-3 {
  Vendor = Check Point Software
  Product = Check Point NGFW
  Lms = Direct
  DataType = "vpn-connection"
  TimeFormat = "epoch"
  Fields = [
    """rt=({time}\d{1,100})""",
    """dpt=({dest_port}[^\s]{1,2000})""",
    """spt=({src_port}[^\s]{1,2000})""",
    """cs2=({rule}.+?)\slayer""",
    """rule_action=({action}[^\s]{1,2000})\s""",
    """direction=({direction}[^\s]{1,2000})\s""",
    """src=({src_ip}[^\s]{1,2000})\s""",
    """dst=({dest_ip}[^\s]{1,2000})\s""",
    """proto=({protocol}[^\s]{1,2000})\s""",
    """originsicname=CN\\=({host}[^\s,;\\]{1,2000})""",
    """act=({result}.+?)\s\w+=""",
    """categoryOutcome=(\/)?({outcome}.+?)\s\w+="""
  
}
```