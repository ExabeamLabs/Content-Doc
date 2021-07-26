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
    """ ({host}[^\s]{1,2000}) [^\s]{1,2000}: IDP_ATTACK_LOG_EVENT: """,
    """: IDP_ATTACK_LOG_EVENT: IDP: at ({time}\d{1,100})""",
    """({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/({src_port}\d{1,100})\W+({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/({dest_port}\d{1,100})""",
    """ for ({protocol}[^\s]{1,2000}) protocol and service ({service}[^\s]{1,2000}) application ({app}[^\s]{1,2000}) by rule ({rule_id}[^\s]{1,2000})""",
    """attack:.+?action=(NONE|({outcome}[^\s,]{1,2000}))""",
    """attack:.+?threat-severity=({alert_severity}[^\s,]{1,2000})""",
    """attack:.+?username=(N\/A|({user}[^,\s]{1,2000}))""",
    """\sname=({alert_name}[^,\s]{1,2000})"""
  ]
}
```