#### Parser Content
```Java
{
Name = leef-checkpoint-alert-1
  Conditions = [ """|Check Point|Anti Malware|""", """signature=""" ]

leef-checkpoint-alert-1 = {
  Vendor = Check Point Software
  Product = Check Point Endpoint Security
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "epoch_sec"
  Fields = [
    """\WdevTime=({time}\d{1,100})""",
    """\WsrcPort=({src_port}\d{1,100})""",
    """\Wservice=({dest_port}\d{1,100})""",
    """\Wurl=(|({malware_url}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsignature=(|({alert_name}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsev=(|({alert_severity}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wifdir=(|({direction}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wifname=(|({src_interface}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Worigin=(|({host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdescription=(|({additional_info}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wproto=(|({protocol}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wmalware_action=(|({alert_type}.+?))(\s{1,100}\w+=|\s{0,100}$)"""
  
}
```