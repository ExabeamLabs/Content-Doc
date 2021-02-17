#### Parser Content
```Java
{
Name = cef-Juniper-network-connection-close
    Vendor = Juniper Networks
    Lms = ArcSight
    DataType = "network-connection"
    TimeFormat = "epoch"
    Conditions = [ """CEF:""", """|RT_FLOW_SESSION_CLOSE|""", """|Session closed|""" ]
    Fields = [
      """\sproto=({protocol}\w+)""",
      """\sin=({bytes_in}\d+)""",
      """\sout=({bytes_out}\d+)""",
      """\srt=({time}\d+)""",
      """\sshost=(|({src_host}.+?))(\s+\w+=|\s*$)""",
      """\ssrc=({src_ip}[a-fA-F\d.:]+)""",
      """\ssourceTranslatedAddress=({src_translated_ip}[a-fA-f\d.:]+)""",
      """\sspt=({src_port}\d+)""",
      """\sdst=({dest_ip}[a-fA-F\d.:]+)""",
      """\sdestinationTranslatedAddress=({dest_translated_ip}[a-fA-F\d.:]+)""",
      """\sdpt=({dest_port}\d+)""",
      """\sduser=(|N\/A|({user}.+?))(\s+\w+=|\s*$)""",
      """\sdvc=(|({host}.+?))(\s+\w+=|\s*$)""",
      """\sdvchost=(|({host}.+?))(\s+\w+=|\s*$)""",
      """\sreason=(|({failure_reason}.+?))(\s+\w+=|\s*$)""",
      """\sdeviceInboundInterface=(|({dest_interface}.+?))(\s+\w+=|\s*$)""",
    ]
  }
```