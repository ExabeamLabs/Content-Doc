#### Parser Content
```Java
{
Name = tenable-security-alert
  Vendor = Tenable.io
  Product = Tenable.io
  Lms = Splunk
  DataType = "security-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"scan":""", """"completed_at":""", """"synopsis":""",""""IO_address":""", """"asset_fqdn":""", """"publication_date":""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """started_at"{1,20}:\s{1,100}"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """asset_fqdn"{1,20}:\s{0,100}"{1,20}({host}[^"]+)""",
    """"{1,20}ipv4"{1,20}:\s{1,100}"{1,20}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """"{1,20}severity"{1,20}:\s{1,100}"{1,20}({alert_severity}[^"]+)""",
    """name"{1,20}:\s{1,100}"{1,20}({alert_name}[^"]+)""",
    """"{1,20}description"{1,20}:\s{1,100}"{1,20}({additional_info}[^"]+?)"{1,20}""",
    """cvss_base_score"{1,20}:\s{1,100}({cvss_base_score}[^,]+)""",
    """cvss3_impact_score"{1,20}:\s{1,100}({cvss3_impact_score}[^,]+)""",
    """exploit_code_maturity"{1,20}:\s{1,100}"{1,20}({exploit_code_maturity}[^"]+)""",
    """see_also"{1,20}:\s{1,100}\[({see_also}[^\]]+)\]""",
    """cve"{1,20}:\s{1,100}\[({cve_id}[^\]]+)\]""", 
    """protocol"{1,20}:\s{1,100}"{1,20}({protocol}[^"]+)""",
    """"state"{1,20}:\s{1,100}"{1,20}({outcome}[^"]+)""",
    """"solution"{1,20}:\s{1,100}"{1,20}((?i)n\/a|({solution}[^"]+))"""
  ]
}
```