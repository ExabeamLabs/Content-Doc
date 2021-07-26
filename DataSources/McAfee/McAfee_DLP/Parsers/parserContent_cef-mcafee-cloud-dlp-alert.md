#### Parser Content
```Java
{
Name = cef-mcafee-cloud-dlp-alert
      Vendor = McAfee
      Product = McAfee DLP
      Lms = ArcSight
      DataType = "dlp-alert"
      TimeFormat = "epoch"
      Conditions = [ """|McAfee|Data Loss Prevention|""", """|DLP: Cloud""" ]
      Fields = [
        """\Wrt=({time}\d{13})""",
        """\Wmsg=({additional_info}.+?)(\s{1,100}\w+=|\s{0,100}$)"""
        """\Wcs2=({target}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
        """\Wcs6=({alert_name}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
        """\Wcs5=({alert_type}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
        """\WeventId=({alert_id}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
        """\WdeviceSeverity=({alert_severity}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
        """\Wdhost=({src_host}[\w.\-]{1,2000})(\s{1,100}\w+=|\s{0,100}$)""",
        """\Wdst=({src_ip}[a-fA-F0-9.:]{1,2000})(\s{1,100}\w+=|\s{0,100}$)""",
        """\Wduser=({user}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
        """\Wfname=({file_name}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
        """\Wfsize=({bytes}\d{1,100})""",
      ]
    }
```