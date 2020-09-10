#### Parser Content
```Java
{
Name = cef-checkpoint-alert-3
  Vendor = Check Point
  Product = Check Point Endpoint Security
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """|Check Point|Anti Malware|""",  """cs4Label=""" ]
  Fields = [
    """exabeam_host=({host}[\w-.]+)""",
    """({host}[\w.\-]+) CEF:""",
    """\Wcp_severity=(?:|({alert_severity}.+?))(\s+\w+=|\s*$)""",
    """\Wrt=({time}\d+)""",
    """\Worigin=({src_ip}[a-fA-F\d.:]+)""",
    """\Woriginsicname=(?:|({user_ou}.+?))(\s+\w+=|\s*$)""",
    """\Wcontract_name=(?:|({alert_name}.+?))(\s+\w+=|\s*$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]+)""",
    """\Wcs(3|6)=(?:|({alert_type}.+?))(\s+\w+=|\s*$)""",
    """\Wcs4=(?:|({alert_name}.+?))(\s+\w+=|\s*$)""",
    """\Wcs4Label=Protection Name cs4=({alert_name}.+?)(\s+\w+=|\s*$)""",
    """\WflexString2=(?:|({additional_info}.+?))(\s+\w+=|\s*$)""",
    """\WdestinationDnsDomain=(?:|({malware_url}.+?))(\s+\w+=|\s*$)""",
    """\Wspt=({src_port}\d+)""",
    """\Wdpt=({dest_port}\d+)""",
    """\Wfname=(|({file_name}.+?(\.({file_ext}\w+))?))(\s+\w+=|\s*$)""",
    """\Wrequest=(|({malware_url}.+?))(\s+\w+=|\s*$)""",
  ]
}
```