#### Parser Content
```Java
{
Name = damballa-leef-alert
  Vendor = Damballa
  Product = Failsafe
  Lms = QRadar
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """|Damballa|Failsafe|""" ]
  Fields = [
    """devTime=({time}\d+)""",
    """exabeam_host=(.+?@\s*)?({host}[^\s]+)""",
    """LEEF:1.0\|Damballa\|Failsafe\|[^\|]+\|({alert_type}[^\|]+)""",
    """LEEF:1.0\|Damballa\|Failsafe\|[^\|]+\|({alert_name}[^\|]+)""",
    """fsIndustryName=({alert_name}[^\t]+)""",
    """fsIncidentSeverity=({alert_severity}[^\t]+)""",
    """\tshost=({src_host}(?!\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[^\t]+)""",
    """\tsrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\tdomain=({malware_domain}[^\t]+)""",
    """\texternalId=({alert_id}[^\t]+)""",
    """\tdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
}
```