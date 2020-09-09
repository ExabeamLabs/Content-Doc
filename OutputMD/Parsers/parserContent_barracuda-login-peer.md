#### Parser Content
```Java
{
Name = barracuda-login-peer
  Vendor = Barracuda Firewall
  Product = Barracuda Firewall
  Lms = Direct
  DataType = "vpn-login"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """ CP-FW Session """, """ Login peer=""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """\sCP-FW Session\s+\S*?({user}[^\-:]+):""",
    """\speer=({src_translated_ip}[a-fA-F\d.:]+)""",
    """\sserver=(|({dest_host}.+?))(\s+\w+=|\s*$)""",
  ]
}
```