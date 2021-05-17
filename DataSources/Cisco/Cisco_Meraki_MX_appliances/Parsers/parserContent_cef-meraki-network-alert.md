#### Parser Content
```Java
{
Name = cef-meraki-network-alert
  Vendor = Cisco
  Product = Cisco Meraki MX appliances
  Lms = ArcSight
  DataType = "network-alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|SkyFormation Cloud Apps Security|""", """|security-threat-detected|""", """NETWORK""", """Cisco Meraki""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\Wend=({time}\d{1,100})""",
    """\Wact=(|({alert_type}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\WrequestClientApplication=(|({app}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\WdestinationServiceName=(|({event_subtype}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\WdeviceMacAddress=(|({src_mac_address}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000}?)(:({src_port}\d{1,100}))?(\s{1,100}\w+=|\s{0,100}$)""",
    """\Woutcome=(|({outcome}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\WflexString2=(|({alert_name}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wmsg=(|({additional_info}.+?))\.?(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wext_protocol=(|({protocol}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdpriv=(|({category}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdproc=(|({process}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """destIp":"({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}):({dest_port}\d{1,100})""",
  ]
}
```