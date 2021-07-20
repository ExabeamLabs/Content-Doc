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
    """devTime=({time}\d{1,100})""",
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]{1,2000})""",
    """LEEF:1.0\|Damballa\|Failsafe\|[^\|]{1,2000}\|({alert_type}[^\|]{1,2000})""",
    """LEEF:1.0\|Damballa\|Failsafe\|[^\|]{1,2000}\|({alert_name}[^\|]{1,2000})""",
    """fsIndustryName=({alert_name}[^\t]{1,2000})""",
    """fsIncidentSeverity=({alert_severity}[^\t]{1,2000})""",
    """\tshost=({src_host}(?!\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[^\t]{1,2000})""",
    """\tsrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\tdomain=({malware_domain}[^\t]{1,2000})""",
    """\texternalId=({alert_id}[^\t]{1,2000})""",
    """\tdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
}
```