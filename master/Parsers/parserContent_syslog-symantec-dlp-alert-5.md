#### Parser Content
```Java
{
Name = syslog-symantec-dlp-alert-5 
    Vendor = Symantec
    Product = Symantec DLP
    Lms = Direct
    DataType = "dlp-alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """rule""","""parsingError""","""Expecting value""", """"message""" ]
    Fields = [
      """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
      """exabeam_host=({host}[^\s]+)""",
      """host"+:\s*"+({host}[^"]+)"+""",
      """"*ingestHost"*:\s*"*({src_host}[^"]+)""",
      """time"*:\s*"*({time}\d+-\d+-\d+T\d+:\d+:\d+)""",
      """severity=\\"+({alert_severity}[^\\]+)\\""",
      """(policy|Policy)\s*\\*=?\\"+({alert_name}[^\\]+)\\"""
      """policy_rules=\\"+({alert_type}[^\\]+)\\""",
      """incident_id=\\"+({alert_id}\d+)\\""",
      """protocol=\\"*({protocol}[^\\]+)\\""",
      """block=\\"*({outcome}[^\\]+)\\""",
      """subject=\\"*({subject}[^\\]+)\\""",
      """sender=\\"*({sender}[^\\]+)\\""",
      """recipients=\\"*({recipients}[^\\]+)\\""",
      """recipients=\\"*({recipients}({recipient}[^,\\]+)[^\\]*)\\"*""",
      """(?i)recipients="*(?=[\w.]+@[\w.])({external_address}[^",]+)("|,|\s*$)""",
      """recipients=\\"*[^@]+@({external_domain}[^,"@\\]+)""",
      """(?i)recipients="*(?=\w+:\/+)({target}[^",]+)("|,|\s*$)""",
      """message"+:\s*"+\s*({addtional_info}[^\\]+\s)"""
    ]
    DupFields = [ "external_address->recipient" ]
}
```