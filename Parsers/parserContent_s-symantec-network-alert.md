#### Parser Content
```Java
{
Name = s-symantec-network-alert
  DataType = "network-alert"
  Conditions = [ """vendor_product="Symantec Endpoint Protection"""", """Somebody is scanning your computer""" ]
  Fields = ${SymantecParserTemplates.s-symantec-alert.Fields}[
    """Local_Host_IP_masked=({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """Remote_Host_IP_masked=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
  ]
}
```