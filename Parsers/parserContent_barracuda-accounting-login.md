#### Parser Content
```Java
{
Name = barracuda-accounting-login
  Vendor = Barracuda
  Product = Barracuda Firewall
  Lms = Direct
  DataType = "vpn-login"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """ CP-FW Session """, """ Accounting LOGIN """ ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """\sCP-FW Session\s+\S*?({user}[^\-:]+):""",
    """\suser=(|({user}.+?))(\s+\w+=|\s*$)""",
    """\sIP=({src_ip}[a-fA-F\d.:]+)""",
    """\sstart="({time}\d\d\d\d/\d\d/\d\d \d\d:\d\d:\d\d)""",
  ]
}
```