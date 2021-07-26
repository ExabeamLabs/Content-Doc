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
      """\sdvchost=({host}[^\s]{1,2000})""",
      """\sexternalId=({alert_id}\d{1,100})""",
      """CEF([^\|]{0,2000}\|){5}({alert_name}[^|]{1,2000})""",
      """CEF([^\|]{0,2000}\|){6}({alert_severity}[^|]{1,2000})""",
      """\smsg=({alert_type}[^=]{1,2000}?)\s{1,100}\w+=""",
      """\smsg=({activity_details}[^=]{1,2000}?)\s{1,100}\w+=""",
      """\smsg=[^=]{1,2000}?(MONITOR|, PERMITTED)\s{1,100}({device_type}[^=]{1,2000}?)\s{1,100}\w+=""",
      """\sshost=({dest_host}[^\s]{1,2000})""",
      """\ssrc=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
      """\ssuser=(({domain}[^\\]{1,2000})\\+)?({user}[^=]{1,2000}?)\s{1,100}\w+="""
    ]
  }
```