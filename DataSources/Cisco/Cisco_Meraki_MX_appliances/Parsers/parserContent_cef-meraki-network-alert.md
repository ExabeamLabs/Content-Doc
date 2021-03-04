#### Parser Content
```Java
{
Name = cef-meraki-network-alert
  Vendor = Cisco
  Product = Cisco Meraki MX appliances
  Lms = ArcSight
  DataType = "network-alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|SkyFormation Cloud Apps Security|""", """|security-threat-detected|""", """NETWORK""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\Wend=({time}\d+)""",
    """\Wact=(|({alert_type}.+?))(\s+\w+=|\s*$)""",
    """\WrequestClientApplication=(|({app}.+?))(\s+\w+=|\s*$)""",
    """\WdestinationServiceName=(|({event_subtype}.+?))(\s+\w+=|\s*$)""",
    """\WdeviceMacAddress=(|({src_mac_address}.+?))(\s+\w+=|\s*$)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+?)(:({src_port}\d+))?(\s+\w+=|\s*$)""",
    """\Woutcome=(|({outcome}.+?))(\s+\w+=|\s*$)""",
    """\WflexString2=(|({alert_name}.+?))(\s+\w+=|\s*$)""",
    """\Wmsg=(|({additional_info}.+?))\.?(\s+\w+=|\s*$)""",
    """\Wext_protocol=(|({protocol}.+?))(\s+\w+=|\s*$)""",
    """\Wdpriv=(|({category}.+?))(\s+\w+=|\s*$)""",
    """\Wdproc=(|({process}.+?))(\s+\w+=|\s*$)""",
  ]
}
```