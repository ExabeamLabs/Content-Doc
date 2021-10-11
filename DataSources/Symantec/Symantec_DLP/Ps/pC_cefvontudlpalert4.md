#### Parser Content
```Java
{
Name = cef-vontu-dlp-alert-4
  Vendor = Symantec
  Product = Symantec DLP
  Lms = Direct
  DataType = "dlp-alert"
  Conditions = [ """|symcdlpsys|""","""|POLICY|""", """|MONITOR_NAME|""", """|APPLICATION_NAME|""" ]
  TimeFormat = "MMM dd, yyyy HH:mm:ss a"
  Fields = [
    """OCCURRED_ON\|({time}\w+\s{1,100}\d{1,2},\s{0,100}\d{1,4}\s{1,100}\d{1,2}:\d{1,2}:\d{1,2}\s{1,100}(AM|PM|am|pm))""",
    """:\d\d\s{1,100}({host}[^\s]{1,2000})\s\|symcdlpsys""",
    """\|\s{0,100}INCIDENT_ID\|({alert_id}\d{1,100})\|""",
    """\|\s{0,100}POLICY\|({alert_name}[^\|]{1,2000})\|""",
    """\|\s{0,100}SEVERITY\|({alert_severity}[^\|]{1,2000})\|""",
    """\|\s{0,100}PROTOCOL\|({protocol}[^\|]{1,2000})\|""",
    """\|\s{0,100}BLOCKED\|(None|({outcome}\w+))\|""",
    """\|\s{0,100}ENDPOINT_USERNAME\|(N\/A|(({domain}[^\s\\\|@]{1,2000})\\+)?({user}[^\s\\\|@]{1,2000}))\|""",
    """\|\s{0,100}TARGET\|(N\/A|({target}[^\|]{1,2000}))\|""",
    """\|\s{0,100}APPLICATION_NAME\|(N\/A|({additional_info}[^\|]{1,2000}))\|""",
    """\|\s{0,100}RULES\|({alert_type}[^\|]{1,2000})\|""",
    """\|\s{0,100}SENDER\|(N\/A|({user_email}([^\|]{1,2000})@({email_domain}[^\|]{1,2000})))""",
    """\|\s{0,100}MACHINE_IP\|({src_ip}[a-fA-F\d\.:]{1,2000})\|""",
    ]
    DupFields = [ "user_email->sender" ]
}
```