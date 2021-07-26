#### Parser Content
```Java
{
Name = barracuda-logout-peer
  Vendor = Barracuda
  Product = Barracuda Firewall
  Lms = Direct
  DataType = "logout"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """ CP-FW Session """, """ Logout peer=""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\sCP-FW Session\s{1,100}\S*?({user}[^\-:]{1,2000}):""",
    """\speer=({src_translated_ip}[a-fA-F\d.:]{1,2000})""",
    """\sserver=(|({dest_host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
  ]
}
```