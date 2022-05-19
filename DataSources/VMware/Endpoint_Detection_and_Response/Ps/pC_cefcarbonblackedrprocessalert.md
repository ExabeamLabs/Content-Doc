#### Parser Content
```Java
{
Name = cef-carbonblack-edr-process-alert
  Vendor = VMware
  Product = Endpoint Detection and Response 
  Lms = Direct
  DataType = "process-alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Carbon Black|""", """|Enterprise EDR|""", """|Threat_Hunter|""", """|Process """, """ was detected by the report """ ]
  Fields = [
    """ ahost=({host}[\w.-]{1,2000})\s""",
    """ rt=({time}\d{1,100})""",
    """ dvchost=({dest_host}[\w.-]{1,2000})\s""",
    """ dvc=({dest_ip}[a-fA-F\d.:]{1,2000})\s""",
    """ duser=({user}[^\s]{1,2000})""",
    """\|Process ({process_name}[^\|]{1,2000}) was detected by the report""",
    """ was detected by the report "{1,20}({alert_name}[^\|"]{1,2000})""",
    """\|Threat_Hunter\|[^\|]{1,200}\|({alert_severity}[^\|]{1,2000})""",
    """({alert_type}Threat_Hunter)""",
    """ cs4="{1,20}({alert_id}[^"]{1,2000})""",
    """\|({event_name}Process [^\|]{1,2000} was detected by the report[^\|]{1,2000})\|""",
    """ cs3=({additional_info}[^\s]{1,2000})"""
  ]


}
```