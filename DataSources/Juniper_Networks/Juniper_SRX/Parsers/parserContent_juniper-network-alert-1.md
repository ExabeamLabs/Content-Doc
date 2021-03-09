#### Parser Content
```Java
{
Name = juniper-network-alert-1
  Vendor = Juniper Networks
  Product = Juniper SRX
  Lms = Syslog
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """ - IDP_ATTACK_LOG_EVENT [""", """ message-type=""", """ destination-interface-name="""" ]
  Fields = [
    """ ({host}[^\s]+) [^\s]+ - IDP_ATTACK_LOG_EVENT """,
    """({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d\-\d\d:\d\d)\s""",
    """\ssource-address="({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """\ssource-port="({src_port}\d+)"""",
    """\sdestination-address="({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """\sdestination-port="({dest_port}\d+)"""",
    """\sprotocol-name="({protocol}[^"]+)"""",
    """\sservice-name="({service}[^"]+)"""",
    """\sapplication-name="({app}[^"]+)"""",
    """\srule-name="({rule_id}[^"]+)"""",
    """\saction="(NONE|({outcome}[^"]+))"""",
    """\sthreat-severity="({alert_severity}[^"]+)"""",
    """\sattack-name="({alert_name}[^"]+)"""",
    """\susername="(N\/A|({user}[^"]+))"""",
    """\srulebase-name="({alert_type}[^"]+)"""
  ]
}
```