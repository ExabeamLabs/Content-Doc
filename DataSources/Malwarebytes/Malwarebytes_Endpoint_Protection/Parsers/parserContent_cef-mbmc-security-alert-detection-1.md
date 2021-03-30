#### Parser Content
```Java
{
Name = cef-mbmc-security-alert-detection-1
    Conditions = [ """CEF:""", """|Malwarebytes|Malwarebytes""", """|Detection|""" ]
    Fields = ${MBMCParserTemplates.cef-malwarebytes-security-alert.Fields} [
      """msg=({additional_info}.+?)\s*\w+=""",
      """filePath=.*?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:({dest_port}\d+))?)"""
    ]
    DupFields = ["src_host->host"]
  }
cef-malwarebytes-security-alert = {
  Vendor = Malwarebytes
  Product = Malwarebytes Endpoint Protection
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Fields = [
    """\Wrt=({time}\w+ \d+ \d\d\d\d \d\d:\d\d:\d\d)""",
    """\Wdvchost=({host}[\w\-.]+)""",
    """({host}[\w\-.]+) CEF:""",
    """([^\|]*\|){6}({alert_severity}\d+)""",
    """\Wdvchost=({src_host}[\w\-.]+)""",
    """\Wdvc=({src_ip}[A-Fa-f:\d.]+)""",
    """\WfilePath=({malware_url}[^=]+?)\s*(\w+=|$)""",
    """\WfileType=({additional_info}[^=]+?)\s*(\w+=|$)""",
    """Process name:\s*({process}({directory}[^=]*?)(\\+({process_name}[^\\]+?))?)\s*(\w+=|$)""",
    """\Wcs1=({alert_name}[^=]+?)\s*(\w+=|$)""",
    """\Wcat=({alert_type}[^=]+?)\s*(\w+=|$)""",
    """\Wsuser=({user}[^=]*?)\s*(\w+=|$)""",
    """\Wact=({action}[^=]+?)\s*(\w+=|$)"""
  ]

```