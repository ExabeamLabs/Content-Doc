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
    """ ({host}[^\s]{1,2000}) [^\s]{1,2000} - IDP_ATTACK_LOG_EVENT """,
    """({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d\-\d\d:\d\d)\s""",
    """\ssource-address="({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """\ssource-port="({src_port}\d{1,100})"""",
    """\sdestination-address="({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """\sdestination-port="({dest_port}\d{1,100})"""",
    """\sprotocol-name="({protocol}[^"]{1,2000})"""",
    """\sservice-name="({service}[^"]{1,2000})"""",
    """\sapplication-name="({app}[^"]{1,2000})"""",
    """\srule-name="({rule_id}[^"]{1,2000})"""",
    """\saction="(NONE|({outcome}[^"]{1,2000}))"""",
    """\sthreat-severity="({alert_severity}[^"]{1,2000})"""",
    """\sattack-name="({alert_name}[^"]{1,2000})"""",
    """\susername="(N\/A|({user}[^"]{1,2000}))"""",
    """\srulebase-name="({alert_type}[^"]{1,2000})"""
  ]
}
```