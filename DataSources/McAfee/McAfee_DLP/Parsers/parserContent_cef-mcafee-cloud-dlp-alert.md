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
        """\Wmsg=({additional_info}.+?)(\s+\w+=|\s*$)"""
        """\Wcs2=({target}.+?)(\s+\w+=|\s*$)""",
        """\Wcs6=({alert_name}.+?)(\s+\w+=|\s*$)""",
        """\Wcs5=({alert_type}.+?)(\s+\w+=|\s*$)""",
        """\WeventId=({alert_id}.+?)(\s+\w+=|\s*$)""",
        """\WdeviceSeverity=({alert_severity}.+?)(\s+\w+=|\s*$)""",
        """\Wdhost=({src_host}[\w.\-]+)(\s+\w+=|\s*$)""",
        """\Wdst=({src_ip}[a-fA-F0-9.:]+)(\s+\w+=|\s*$)""",
        """\Wduser=({user}.+?)(\s+\w+=|\s*$)""",
        """\Wfname=({file_name}.+?)(\s+\w+=|\s*$)""",
        """\Wfsize=({bytes}\d+)""",
      ]
    }
```