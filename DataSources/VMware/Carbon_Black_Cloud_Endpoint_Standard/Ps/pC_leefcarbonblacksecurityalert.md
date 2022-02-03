#### Parser Content
```Java
{
Name = leef-carbonblack-security-alert
  Vendor = VMware
  Product = Carbon Black Cloud Endpoint Standard
  Lms = QRadar
  DataType = "alert"
  TimeFormat = "MMM-dd-yyyy HH:mm:ss z"
  Conditions = [ """LEEF:""", """|CarbonBlack|CbDefense|""", """threatIndicators=""", """incidentId=""" ]
  Fields = [
    """devTime=({time}\w{1,3}-\d\d-\d\d\d\d\s\d\d:\d\d:\d\d\s\w{1,3})""",
    """deviceName =({host}[^\s]{1,2000})""",
    """userName =(None|({user}[^=]{1,2000}?))\s{1,100}\w+=""",
    """email=({user_email}[^@]{1,2000}@[^\s]{1,2000})""",
    """\WcommandLine=(None|({command_line}[^\n]{1,2000}?))\s{1,100}\w+=""",
    """threatIndicators=({alert_name}[^=]{1,2000}?)\s{1,100}\w+=""",
    """sev=({alert_severity}\d{1,100})""",
    """eventType=({alert_type}[^=]{1,2000}?)\s{1,100}\w+=""",
    """src=({src_ip}[a-fA-F\d:.]{1,2000})""",
    """dst=({dest_ip}[a-fA-F\d:.]{1,2000})"""
  ]


}
```