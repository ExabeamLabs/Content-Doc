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
    """\Wact=(|({activity}.+?))(\s+\w+=|\s*$)""",
    """\Wrt=({time}\d+)""",
    """\Wshost=(|({src_host}.+?))(\s+\w+=|\s*$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wspt=({src_port}\d+)""",
    """\Wdhost=(|({dest_host}.+?))(\s+\w+=|\s*$)""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]+)""",
    """\Wdpt=({dest_port}\d+)""",
    """\WdestinationServiceName=(|({service}.+?))(\s+\w+=|\s*$)""",
    """\Wdvchost=(|({host}.+?))(\s+\w+=|\s*$)""",
    """\Wcat=({event_subtype}.+?)(\s+\w+=|\s*$)""",
    """\Wapp\\?="({app}[^"]+)"""",
    """\Wmsg=({additional_info}.+?),?(\s+\w+=|\s*$)""",
  ]
}
```