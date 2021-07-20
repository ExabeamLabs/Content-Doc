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
    """sender=(?!\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(N\/A|({user_email}[^,]{1,2000}))""",
    """incident_id=({alert_id}\d{1,100})""",
    """\sprotocol=({alert_type}[^,]{1,2000})""",
    """\spolicy=({alert_type}[^,]{1,2000})""",
    """\sseverity=({alert_severity}[^,]{1,2000})""",
    """\srules=({alert_name}[^,\)]{1,2000}\)?)""",
    """\sdlp_host=({host}[^,]{1,2000})""",
    """blocked=({outcome}[^,]{1,2000})""",
    """recipients=({target}.+), severity=""",
    """file_name=({file_name}[^,]{1,2000})\s{0,100}""",
    """endpoint_machine_ip=({src_ip}[^,]{1,2000})""",
    """endpoint_user_id=({domain}[^\\]{1,2000})\\({user}[^,]{1,2000})"""
   ]
}
```