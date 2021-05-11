#### Parser Content
```Java
{
Name = cef-mcafee-usb
    Vendor = McAfee
    Product = McAfee DLP
    Lms = ArcSight
    DataType = "usb-activity"
    TimeFormat = "epoch"
    Conditions = [ """CEF:""", """|McAfee|ePolicy""", """|Threat:""" ]
    Fields = [ """\srt=({time}\d{1,100})""",
      """\sdvchost=({host}[^\s]+)""",
      """\sexternalId=({alert_id}\d{1,100})""",
      """CEF([^\|]*\|){5}({alert_name}[^|]+)""",
      """CEF([^\|]*\|){6}({alert_severity}[^|]+)""",
      """\smsg=({alert_type}[^=]+?)\s{1,100}\w+=""",
      """\smsg=({activity_details}[^=]+?)\s{1,100}\w+=""",
      """\smsg=[^=]+?(MONITOR|, PERMITTED)\s{1,100}({device_type}[^=]+?)\s{1,100}\w+=""",
      """\sshost=({dest_host}[^\s]+)""",
      """\ssrc=({dest_ip}[A-Fa-f:\d.]+)""",
      """\ssuser=(({domain}[^\\]+)\\+)?({user}[^=]+?)\s{1,100}\w+="""
    ]
  }
```