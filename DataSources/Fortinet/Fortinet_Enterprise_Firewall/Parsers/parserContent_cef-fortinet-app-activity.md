#### Parser Content
```Java
{
Name = cef-fortinet-app-activity
  Vendor = Fortinet
  Product = Fortinet Enterprise Firewall
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Fortinet|Fortigate|""", """cn1Label=Duration""", """|utm: app-ctrl|""" ]
  Fields = [
    """\Wproto=({protocol}\w+)""",
    """\Wact=(|({activity}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wrt=({time}\d{1,100})""",
    """\Wshost=(|({src_host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wspt=({src_port}\d{1,100})""",
    """\Wdhost=(|({dest_host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wdpt=({dest_port}\d{1,100})""",
    """\WdestinationServiceName=(|({service}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdvchost=(|({host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcat=({event_subtype}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wapp\\?="({app}[^"]{1,2000})"""",
    """\Wmsg=({additional_info}.+?),?(\s{1,100}\w+=|\s{0,100}$)""",
  ]
}
```