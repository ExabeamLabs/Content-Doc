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
    """CEF:([^\|]*\|){5}({alert_name}[^\|]+)\|({alert_severity}[^\|]+)""",
    """\Wmsg=(|({additional_info}.+?))(\s+\w+=|\s*$)""",
    """\Wdvc=(|({host}.+?))(\s+\w+=|\s*$)""",
    """\Wrt=({time}\d+)""",
    """\Wsrc=({dest_ip}[a-fA-F\d.:]+)""",
    """\Wduser=(|({user}.+?))(\s+\w+=|\s*$)""",
    """\Wshostname=(|({dest_host}.+?))(\s+\w+=|\s*$)""",
    """\Wsmac=(|({dest_mac}.+?))(\s+\w+=|\s*$)""",
    """\Wdhost=(|({src_shost}.+?))(\s+\w+=|\s*$)""",
  ]
}
```