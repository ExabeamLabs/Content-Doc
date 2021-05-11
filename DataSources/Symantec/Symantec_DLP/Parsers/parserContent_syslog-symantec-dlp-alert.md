#### Parser Content
```Java
{
Name = syslog-symantec-dlp-alert
  Conditions = [ """endpoint_machine""", """policy_name""", """incident_snapshot=""" ]
  Fields = ${SymantecParserTemplates.syslog-symantec-dlp-alert.Fields} [
      """(?i)incident_snapshot=[^,]*?({alert_id}\d{1,100}),""",
      """(?i)incident_snapshot="{0,20}\w+:\/+[^\s]*?((?!\d{1,3}\.\d{1,3}\.\d{1,3})({top_domain}[^\/\.\s]+(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|local))+))(\/|\||"|\s{1,100}\w+=|\s{0,100}$)"""
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
      """\d\d:\d\d:\d\d ({host}[\w.\-]+)\s{1,100}""",
      """(?i)severity="{0,20}({alert_severity}[^",]+)("|,|\s{0,100}$)""",
      """(?i)policy_name="{0,20}({alert_name}[^",]+)("|,|\s{0,100}$)""",
      """(?i)policy_rules="{0,20}({alert_type}[^",]+)("|,|\s{0,100}$)""",
      """(?i)incident_id="{0,20}({alert_id}\d{1,100})("|,|\s{0,100}$)""",
      """(?i)protocol="{0,20}({protocol}[^",]+)("|,|\s{0,100}$)""",
      """(?i)blocked="{0,20}(?:N\/A|None|({outcome}[^",]+))("|,|\s{0,100}$)""",
      """(?i)subject="{0,20}(?:N\/A|({subject}[^",]+))("|,|\s{0,100}$)""",
      """\s(?i)file_name="{0,20}(?:N\/A|({file_name}[^",]+))\s{0,100}("|,|\s{0,100}$)""",
      """(?i)endpoint_username="{0,20}(N\/A|(({domain}[^\\]+)\\+)?({user}[^",]+))("|,|\s{0,100}$)""",
      """(?i)endpoint_machine="{0,20}(N\/A|({dest_host}[^",]+))("|,|\s{0,100}$)""",
      """(?i)machine_ip="{0,20}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """(?i)sender="{0,20}(?=[\w.]+@[\w.])({sender}[^",]+)("|,|\s{0,100}$)""",
      """(?i)sender="{0,20}(?=[\w.]+@[\w.])({user}[^",]+)("|,|\s{0,100}$)""",
      """(?i)recipients="{0,20}(?=[\w.]+@[\w.])({recipients}[^",]+)("|,|\s{0,100}$)""",
      """(?i)recipients="{0,20}(?=[\w.]+@[\w.])({external_address}[^",]+)("|,|\s{0,100}$)""",
      """(?i)recipients="{0,20}[^@]+@({external_domain}[^,"@]+)("|,|\s{0,100}$)""",
      """(?i)recipients="{0,20}(?=\w+:\/+)({target}[^",]+)("|,|\s{0,100}$)"""
    ]

```