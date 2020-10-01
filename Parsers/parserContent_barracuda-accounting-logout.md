#### Parser Content
```Java
{
Name = barracuda-accounting-logout
  Vendor = Barracuda
  Product = Barracuda Firewall
  Lms = Direct
  DataType = "logout"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """ CP-FW Session """, """ Accounting LOGOUT """ ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """\sCP-FW Session\s+\S*?({user}[^\-:]+):""",
    """\suser=(|({user}.+?))(\s+\w+=|\s*$)""",
    """\sIP=({src_ip}[a-fA-F\d.:]+)""",
    """\sstart="({time}\d\d\d\d/\d\d/\d\d \d\d:\d\d:\d\d)""",
    """\sduration=(|({duration}.+?))(\s+\w+=|\s*$)""",
    """\sinBytes=({bytes_in}\d+)""",
    """\soutBytes=({bytes_out}\d+)""",
  ]
}
```