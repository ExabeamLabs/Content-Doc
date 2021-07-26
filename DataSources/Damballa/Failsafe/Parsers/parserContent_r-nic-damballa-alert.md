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
    """\s{1,100}({host}[^\s]{1,2000})\s{1,100}Failsafe\s{1,100}\d{1,100}""",
    """Damballa\|Failsafe\|[^|]{1,2000}?\|({alert_name}[^|]{1,2000})\|""",
    """Damballa\|Failsafe\|[^|]{1,2000}?\|({alert_type}[^|]{1,2000})\|""",
    """\|cs2=({alert_type}[^|]{1,2000})""",
    """\|msg=({alert_name}[^|]{1,2000})""",
    """\|cfp1=({alert_severity}[^\|]{1,2000})""",
    """\|src=({src_ip}[^\|]{1,2000})""",
    """\|shost=(?:((\d{1,100}\.){3}\d{1,100})|({src_host}[^\|]{1,2000}))""",
    """\|cs6=({alert_id}[^\|]{1,2000})"""
  ]
}
```