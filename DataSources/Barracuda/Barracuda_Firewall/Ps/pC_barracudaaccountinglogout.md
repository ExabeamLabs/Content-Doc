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
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\sCP-FW Session\s{1,100}\S*?({user}[^\-:]{1,2000}):""",
    """\suser=(|({user}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\sIP=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\sstart="({time}\d\d\d\d/\d\d/\d\d \d\d:\d\d:\d\d)""",
    """\sduration=(|({duration}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\sinBytes=({bytes_in}\d{1,100})""",
    """\soutBytes=({bytes_out}\d{1,100})""",
  ]
}
```