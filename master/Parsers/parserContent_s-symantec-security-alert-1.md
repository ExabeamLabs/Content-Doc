#### Parser Content
```Java
{
Name = s-symantec-security-alert-1
  DataType = "alert"
  Conditions = [ """vendor_product="Symantec Endpoint Protection"""", """symantec_ep_security""" ]
  Fields = ${SymantecParserTemplates.s-symantec-alert.Fields}[
    """orig_host=({src_host}.*?),\s\w+=""",
    """src_masked="({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""", 
    """Local_Host_IP_masked="({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """orig_source="({process}[^"]+\\({process_name}[^"]+))"""", 
  ]
}
```