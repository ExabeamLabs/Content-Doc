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
    """started_at"+:\s+"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
    """asset_fqdn"+:\s*"+({host}[^"]+)""",
    """"+ipv4"+:\s+"+({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """"+severity"+:\s+"+({alert_severity}[^"]+)""",
    """name"+:\s+"+({alert_name}[^"]+)""",
    """"+description"+:\s+"+({additional_info}[^"]+?)"+""",
    """cvss_base_score"+:\s+({cvss_base_score}[^,]+)""",
    """cvss3_impact_score"+:\s+({cvss3_impact_score}[^,]+)""",
    """exploit_code_maturity"+:\s+"+({exploit_code_maturity}[^"]+)""",
    """see_also"+:\s+\[({see_also}[^\]]+)\]""",
    """cve"+:\s+\[({cve_id}[^\]]+)\]""", 
    """protocol"+:\s+"+({protocol}[^"]+)""",
    """"state"+:\s+"+({outcome}[^"]+)""",
    """"solution"+:\s+"+((?i)n\/a|({solution}[^"]+))"""
  ]
}
```