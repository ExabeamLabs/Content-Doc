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
    """\sCP-FW Session\s{1,100}\S*?({user}[^\-:]+):""",
    """\suser=(|({user}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\sIP=({src_ip}[a-fA-F\d.:]+)""",
    """\sstart="({time}\d\d\d\d/\d\d/\d\d \d\d:\d\d:\d\d)""",
  ]
}
```