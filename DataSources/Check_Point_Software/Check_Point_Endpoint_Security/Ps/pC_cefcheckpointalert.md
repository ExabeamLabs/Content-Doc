#### Parser Content
```Java
{
Name = cef-checkpoint-alert
  Vendor = Check Point Software
  Product = Check Point Endpoint Security
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """|Check Point|New Anti Virus|""",  """cs4Label=""" ]
  Fields = [
    """exabeam_host=({host}[\w-.]{1,2000})""",
    """({host}[\w.\-]{1,2000}) CEF:""",
    """\Wcp_severity=(?:|({alert_severity}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wrt=({time}\d{1,100})""",
    """\Worigin=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Woriginsicname=(?:|({user_ou}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcontract_name=(?:|({alert_name}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wcs(3|6)=(?:|({alert_type}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcs4=(?:|({alert_name}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcs4Label=Protection Name cs4=({alert_name}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\WflexString2=(?:|({additional_info}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\WdestinationDnsDomain=(?:|({malware_url}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wspt=({src_port}\d{1,100})""",
    """\Wdpt=({dest_port}\d{1,100})""",
    """\Wfname=(|({file_name}.+?(\.({file_ext}\w+))?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wrequest=(|({malware_url}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
  ]


}
```