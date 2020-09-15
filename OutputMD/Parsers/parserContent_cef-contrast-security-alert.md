#### Parser Content
```Java
{
Name = cef-contrast-security-alert
  Vendor = Contrast Security
  Product = Contrast Security
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss.SSS"
  Conditions = [ """CEF:""", """|Contrast Security|""", """|SECURITY|""" ]
  Fields = [
    """({time}\w+ \d+ \d\d\d\d \d\d:\d\d:\d\d\.\d+)\s+({host}\S+)\s+CEF:([^\|]*\|){4}(|({alert_type}[^\|]+))\|(|({additional_info}[^\|]+))\|(|({alert_severity}[^\|]+))\|""",
    """\Wpri=(|({alert_name}.+?))(\s+\w+=|\s*$)""",
    """\Wsrc=(0:0:0:0:0:0:0:1|({src_ip}[a-fA-F\d.:]+))""",
    """\Wspt=(0|({src_port}\d+))""",
    """\Wrequest=(|({malware_url}.+?))(\s+\w+=|\s*$)""",
    """\Wapp=(|({process_name}.+?))(\s+\w+=|\s*$)""",
    """\Woutcome=(|({outcome}.+?))(\s+\w+=|\s*$)""",
  ]
}
```