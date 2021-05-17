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
        """\Wshost=({host}[\w\-\.]{1,2000})\s{0,100}(\w+=|$)""",
        """\WeventId=({alert_id}\d{1,100})""",
        """\Wcs1=({alert_type}.+?)\s{0,100}(\w+=|$)""",
        """\Wcat=({alert_name}.+?)\s{0,100}(\w+=|$)""",
        """\Wsuser=(({domain}[^\\]{1,2000})\\+)?({user}[^\\\s]{1,2000})\s{0,100}(\w+=[^\/]|$)""",
        """\Wsntdom=({domain}.+?)\s{0,100}(\w+=|$)""",
        """\Wfname=({file_name}[^,]{1,2000}),\s{0,100}({target}.+?)\s{0,100}(\w+=|$)""",
        """\Wfsize=({bytes}\d{1,100})\s{0,100}(\w+=|$)""",
        """\WrequestUrlHost=({dest_host}[\w\-\.]{1,2000})\s{0,100}(\w+=|$)""",
        """\|McAfee EPO DLPE.*?\|({alert_severity}[^\|]{1,2000})\|""",
        """\WcategoryOutcome=[\\\/]{0,2000}({outcome}[^\\\/]{1,2000}?)\s{0,100}(\w+=|$)""",
        """\Wsproc=({additional_info}.+?)\s{0,100}(\w+=|$)"""
      ]
    }
```