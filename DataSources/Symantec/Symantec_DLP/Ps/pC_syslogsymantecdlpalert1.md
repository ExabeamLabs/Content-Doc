#### Parser Content
```Java
{
Name = syslog-symantec-dlp-alert-1
  Conditions = [ """Incident_Snapshot=""", """Device_Instance_ID=""", """Policy_Rules=""" ]
  Fields = ${SymantecParserTemplates.syslog-symantec-dlp-alert.Fields} [
      """(?i)incident_snapshot=[^,]{0,2000}?({alert_id}\d{1,100}),""",
      """(?i)incident_snapshot=((?!\d{1,3}\.\d{1,3}\.\d{1,3})({full_url}(\w+:\/+)?({web_domain}[^\\\/]{1,2000})[^\s]{1,2000}))\s{1,100}\w+=|\s{0,100}$"""
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
      """exabeam_host=({host}[^\s]{1,2000})""",
      """\d\d:\d\d:\d\d ({host}[\w.\-]{1,2000})\s{1,100}""",
      """(?i)severity="{0,20}({alert_severity}[^",]{1,2000})("|,|\s{0,100}$)""",
      """(?i)policy_name="{0,20}({alert_name}[^",]{1,2000})("|,|\s{0,100}$)""",
      """(?i)policy_rules="{0,20}({alert_type}[^",]{1,2000})("|,|\s{0,100}$)""",
      """(?i)incident_id="{0,20}({alert_id}\d{1,100})("|,|\s{0,100}$)""",
      """(?i)protocol="{0,20}({protocol}[^",]{1,2000})("|,|\s{0,100}$)""",
      """(?i)blocked="{0,20}(?:N\/A|None|({outcome}[^",]{1,2000}))("|,|\s{0,100}$)""",
      """(?i)subject="{0,20}(?:N\/A|({subject}[^",]{1,2000}))("|,|\s{0,100}$)""",
      """\s(?i)file_name="{0,20}(?:N\/A|({file_name}[^",]{1,2000}))\s{0,100}("|,|\s{0,100}$)""",
      """(?i)endpoint_username="{0,20}(N\/A|(({domain}[^\\]{1,2000})\\+)?({user}[^",]{1,2000}))("|,|\s{0,100}$)""",
      """(?i)endpoint_machine="{0,20}(N\/A|({dest_host}[^",]{1,2000}))("|,|\s{0,100}$)""",
      """(?i)machine_ip="{0,20}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """(?i)sender="{0,20}(?=[\w.]{1,2000}@[\w.])({sender}[^",]{1,2000})("|,|\s{0,100}$)""",
      """(?i)sender="{0,20}(?=[\w.]{1,2000}@[\w.])({user}[^",]{1,2000})("|,|\s{0,100}$)""",
      """(?i)recipients="{0,20}(?=[\w.]{1,2000}@[\w.])({recipients}[^",]{1,2000})("|,|\s{0,100}$)""",
      """(?i)recipients="{0,20}(?=[\w.]{1,2000}@[\w.])({external_address}[^",]{1,2000})("|,|\s{0,100}$)""",
      """(?i)recipients="{0,20}(?=\w+:\/+)({target}[^",]{1,2000})("|,|\s{0,100}$)"""
    ]

```