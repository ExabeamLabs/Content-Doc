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
    """\|start=({time}\d+)""",
    """\s+({host}[^\s]+)\s+Failsafe\s+\d+""",
    """Damballa\|Failsafe\|.+?\|({alert_name}[^|]+)\|""",
    """Damballa\|Failsafe\|.+?\|({alert_type}[^|]+)\|""",
    """\|cs2=({alert_type}[^|]+)""",
    """\|msg=({alert_name}[^|]+)""",
    """\|cfp1=({alert_severity}[^\|]+)""",
    """\|src=({src_ip}[^\|]+)""",
    """\|shost=(?:((\d+\.){3}\d+)|({src_host}[^\|]+))""",
    """\|cs6=({alert_id}[^\|]+)"""
  ]
}
```