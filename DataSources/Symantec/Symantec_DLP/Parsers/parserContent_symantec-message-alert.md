#### Parser Content
```Java
{
Name = symantec-message-alert
  Vendor = Symantec
  Product = Symantec DLP
  Lms = Direct
  DataType = "dlp-alert"
  TimeFormat = "MMM dd, yyyy HH:mm:ss"
  Conditions = ["""protocol=""","""policy=""","""rules=""" ,"""file_name=""","""dlp_host=""" ]
  Fields = [
    """ocurred_on=({time}.+)\s(PM|AM|am|pm|Am|Pm), reported""",
    """sender=(?!\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(N\/A|({user_email}[^,]+))""",
    """incident_id=({alert_id}\d{1,100})""",
    """\sprotocol=({alert_type}[^,]+)""",
    """\spolicy=({alert_type}[^,]+)""",
    """\sseverity=({alert_severity}[^,]+)""",
    """\srules=({alert_name}[^,\)]+\)?)""",
    """\sdlp_host=({host}[^,]+)""",
    """blocked=({outcome}[^,]+)""",
    """recipients=({target}.+), severity=""",
    """file_name=({file_name}[^,]+)\s{0,100}""",
    """endpoint_machine_ip=({src_ip}[^,]+)""",
    """endpoint_user_id=({domain}[^\\]+)\\({user}[^,]+)"""
   ]
}
```