#### Parser Content
```Java
{
Name = checkpoint-firewall-2
  DataType = "alert"
  Conditions = [ """|Check Point|VPN-1|""", """/Access"""]
  Fields = ${CheckpointParserTemplates.checkpoint-firewall-3.Fields} [
    """originsicname=CN\\=({host}[^\s,;\\]{1,2000})""",
    """act=({result}.+?)\s\w+=""",
    """categoryOutcome=(\/)?({outcome}.+?)\s\w+="""
  ]
} 

{
  Name = cef-checkpoint-network-alert
  Vendor = Check Point Software
  Product = Check Point Threat Prevention
  Lms = ArcSight
  DataType = "network-alert"
  TimeFormat = "epoch"
  Conditions = [ """|Check Point|SmartDefense""", """cp_severity=""" ]
  Fields = [
    """({host}[\w.\-]{1,2000}) CEF:""",
    """\Wcp_severity=(?:|({alert_severity}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wrt=({time}\d{1,100})""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\Woriginsicname=(?:|({user_ou}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wmsg=(?:|({alert_type}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdescription_url=(?:|({malware_url}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcs4=(?:|({alert_name}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Winspection_information=(?:|({alert_name}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\WflexString2=(?:|({additional_info}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wproto=(?:|({protocol}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wspt=({src_port}\d{1,100})""",
    """\Wdpt=({dest_port}\d{1,100})""",
  ]
}
```