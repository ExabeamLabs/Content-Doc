#### Parser Content
```Java
{
Name = juniper-network-alert-2
  Vendor = Juniper Networks
  Product = Juniper SRX
  Lms = Syslog
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """: IDP_ATTACK_LOG_EVENT: IDP: """,  """ protocol and service """, """ in policy """ ]
  Fields = [
    """ ({host}[^\s]+) [^\s]+: IDP_ATTACK_LOG_EVENT: """,
    """: IDP_ATTACK_LOG_EVENT: IDP: at ({time}\d+)""",
    """({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/({src_port}\d+)\W+({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/({dest_port}\d+)""",
    """ for ({protocol}[^\s]+) protocol and service ({service}[^\s]+) application ({app}[^\s]+) by rule ({rule_id}[^\s]+)""",
    """attack:.+?action=(NONE|({outcome}[^\s,]+))""",
    """attack:.+?threat-severity=({alert_severity}[^\s,]+)""",
    """attack:.+?username=(N\/A|({user}[^,\s]+))""",
    """\sname=({alert_name}[^,\s]+)"""
  ]
}
```