#### Parser Content
```Java
{
Name = cef-Juniper-network-connection-close
    Vendor = Juniper Networks
  Product = Juniper SRX
    Lms = ArcSight
    DataType = "network-connection"
    TimeFormat = "epoch"
    Conditions = [ """CEF:""", """|RT_FLOW_SESSION_CLOSE|""", """|Session closed|""" ]
    Fields = [
      """\sproto=({protocol}\w+)""",
      """\sin=({bytes_in}\d{1,100})""",
      """\sout=({bytes_out}\d{1,100})""",
      """\srt=({time}\d{1,100})""",
      """\sshost=(|({src_host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
      """\ssrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
      """\ssourceTranslatedAddress=({src_translated_ip}[a-fA-f\d.:]{1,2000})""",
      """\sspt=({src_port}\d{1,100})""",
      """\sdst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
      """\sdestinationTranslatedAddress=({dest_translated_ip}[a-fA-F\d.:]{1,2000})""",
      """\sdpt=({dest_port}\d{1,100})""",
      """\sduser=(|N\/A|({user}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
      """\sdvc=(|({host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
      """\sdvchost=(|({host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
      """\sreason=(|({failure_reason}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
      """\sdeviceInboundInterface=(|({dest_interface}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    ]
  }
```