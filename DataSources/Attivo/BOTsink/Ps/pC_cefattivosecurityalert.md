#### Parser Content
```Java
{
Name = cef-attivo-security-alert
  Vendor = Attivo
  Product = BOTsink
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Attivo|BOTsink|""" ]
  Fields = [
    """CEF:([^\|]{0,2000}\|){5}({alert_name}[^\|]{1,2000})\|({alert_severity}[^\|]{1,2000})""",
    """\Wmsg=(|({additional_info}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdvc=(|({host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wrt=({time}\d{1,100})""",
    """\Wsrc=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wduser=(|({user}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wshostname=(|({dest_host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsmac=(|({dest_mac}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdhost=(|({src_shost}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
  ]


}
```