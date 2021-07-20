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
    """({time}\w+ \d{1,100} \d\d\d\d \d\d:\d\d:\d\d\.\d{1,100})\s{1,100}({host}\S+)\s{1,100}CEF:([^\|]{0,2000}\|){4}(|({alert_type}[^\|]{1,2000}))\|(|({additional_info}[^\|]{1,2000}))\|(|({alert_severity}[^\|]{1,2000}))\|""",
    """\Wpri=(|({alert_name}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsrc=(0:0:0:0:0:0:0:1|({src_ip}[a-fA-F\d.:]{1,2000}))""",
    """\Wspt=(0|({src_port}\d{1,100}))""",
    """\Wrequest=(|({malware_url}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wapp=(|({process_name}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Woutcome=(|({outcome}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
  ]
}
```