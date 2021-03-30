#### Parser Content
```Java
{
Name = syslog-symantec-dlp-alert-4
  Conditions = [ """,endpoint_machine=""", """,policy=""", """,incident_id=""" ]
  Fields = ${SymantecParserTemplates.syslog-symantec-dlp-alert.Fields} [
    """(?i)policy="*({alert_name}[^",]+)("|,|\s*$)""",
    """(?i)application_name="*(?:N\/A|({process_name}.+?))\s*("|,|\s*$)""",
    """\s*(?i)file_name="*(?:N\/A|({file_name}[^",]+))\s*("|,|\s*$)"""
  ]
}
syslog-symantec-dlp-alert = {
    Vendor = Symantec
    Product = Symantec DLP
    Lms = Direct
    DataType = "dlp-alert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Fields = [
      """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
      """exabeam_host=({host}[^\s]+)""",
      """\d\d:\d\d:\d\d ({host}[\w.\-]+)\s+""",
      """(?i)severity="*({alert_severity}[^",]+)("|,|\s*$)""",
      """(?i)policy_name="*({alert_name}[^",]+)("|,|\s*$)""",
      """(?i)policy_rules="*({alert_type}[^",]+)("|,|\s*$)""",
      """(?i)incident_id="*({alert_id}\d+)("|,|\s*$)""",
      """(?i)protocol="*({protocol}[^",]+)("|,|\s*$)""",
      """(?i)blocked="*(?:N\/A|None|({outcome}[^",]+))("|,|\s*$)""",
      """(?i)subject="*(?:N\/A|({subject}[^",]+))("|,|\s*$)""",
      """\s(?i)file_name="*(?:N\/A|({file_name}[^",]+))\s*("|,|\s*$)""",
      """(?i)endpoint_username="*(N\/A|(({domain}[^\\]+)\\+)?({user}[^",]+))("|,|\s*$)""",
      """(?i)endpoint_machine="*(N\/A|({dest_host}[^",]+))("|,|\s*$)""",
      """(?i)machine_ip="*({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """(?i)sender="*(?=[\w.]+@[\w.])({sender}[^",]+)("|,|\s*$)""",
      """(?i)sender="*(?=[\w.]+@[\w.])({user}[^",]+)("|,|\s*$)""",
      """(?i)recipients="*(?=[\w.]+@[\w.])({recipients}[^",]+)("|,|\s*$)""",
      """(?i)recipients="*(?=[\w.]+@[\w.])({external_address}[^",]+)("|,|\s*$)""",
      """(?i)recipients="*[^@]+@({external_domain}[^,"@]+)("|,|\s*$)""",
      """(?i)recipients="*(?=\w+:\/+)({target}[^",]+)("|,|\s*$)"""
    ]

```