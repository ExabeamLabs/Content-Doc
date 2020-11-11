#### Parser Content
```Java
{
Name = cef-mcafee-epo-dlp-alert
      Vendor = McAfee
      Product = McAfee DLP
      Lms = ArcSight
      DataType = "dlp-alert"
      TimeFormat = "epoch"
      Conditions = [ """|McAfee|DLPE|""", """|McAfee EPO DLPE""" ]
      Fields = [
        """\Wrt=({time}\d{13})""",
        """\Wshost=({host}[\w\-\.]+)\s*(\w+=|$)""",
        """\WeventId=({alert_id}\d+)""",
        """\Wcs1=({alert_type}.+?)\s*(\w+=|$)""",
        """\Wcat=({alert_name}.+?)\s*(\w+=|$)""",
        """\Wsuser=(({domain}[^\\]+)\\+)?({user}[^\\\s]+)\s*(\w+=[^\/]|$)""",
        """\Wsntdom=({domain}.+?)\s*(\w+=|$)""",
        """\Wfname=({file_name}[^,]+),\s*({target}.+?)\s*(\w+=|$)""",
        """\Wfsize=({bytes}\d+)\s*(\w+=|$)""",
        """\WrequestUrlHost=({dest_host}[\w\-\.]+)\s*(\w+=|$)""",
        """\|McAfee EPO DLPE.*?\|({alert_severity}[^\|]+)\|""",
        """\WcategoryOutcome=[\\\/]*({outcome}[^\\\/]+?)\s*(\w+=|$)""",
        """\Wsproc=({additional_info}.+?)\s*(\w+=|$)"""
      ]
    }
```