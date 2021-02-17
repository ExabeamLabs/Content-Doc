#### Parser Content
```Java
{
Name = checkpoint-network-alert-3
  DataType = "alert"
  Conditions = [ """CheckPoint""", """product:"Anti Malware"""" ]
  Fields = ${CheckpointParserTemplates.checkpoint-firewall-1.Fields}[
    """malware_action:"({alert_type}[^"]+)""",
    """protection_name:"({alert_name}[^"]+)""",
    """severity:"({alert_severity}[^"]+)""""
  ]
}
```