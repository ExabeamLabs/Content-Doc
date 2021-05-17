#### Parser Content
```Java
{
Name = cef-fortinet-network-connection
  Vendor = Fortinet
  Product = Fortinet Enterprise Firewall
  Lms = ArcSight
  DataType = "network-connection"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Fortinet|Fortigate|""", """cn1Label=Duration""", """|traffic: """ ]
  Fields = [
    """\Wproto=({protocol}\w+)""",
    """\Wact=(|({action}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wrt=({time}\d{1,100})""",
    """\Wshost=(|({src_host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wspt=({src_port}\d{1,100})""",
    """\Wdhost=(|({dest_host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wdpt=({dest_port}\d{1,100})""",
    """\WdestinationServiceName=(|({service}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdvchost=(|({host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\WdeviceOutboundInterface=({dest_interface}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\WdeviceInboundInterface=({src_interface}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wout=({bytes_out}\d{1,100})""",
    """\Win=({bytes_in}\d{1,100})""",
  ]
  DupFields = [ "action->outcome" ]
}
```