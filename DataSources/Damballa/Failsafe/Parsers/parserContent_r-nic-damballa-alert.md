#### Parser Content
```Java
{
Name = r-nic-damballa-alert
  Vendor = Damballa
  Product = Failsafe
  Lms = RsaSa
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """Damballa|Failsafe|""", """msg=infected""" ]
  Fields = [
    """\|start=({time}\d{1,100})""",
    """\s{1,100}({host}[^\s]+)\s{1,100}Failsafe\s{1,100}\d{1,100}""",
    """Damballa\|Failsafe\|[^|]+?\|({alert_name}[^|]+)\|""",
    """Damballa\|Failsafe\|[^|]+?\|({alert_type}[^|]+)\|""",
    """\|cs2=({alert_type}[^|]+)""",
    """\|msg=({alert_name}[^|]+)""",
    """\|cfp1=({alert_severity}[^\|]+)""",
    """\|src=({src_ip}[^\|]+)""",
    """\|shost=(?:((\d{1,100}\.){3}\d{1,100})|({src_host}[^\|]+))""",
    """\|cs6=({alert_id}[^\|]+)"""
  ]
}
```