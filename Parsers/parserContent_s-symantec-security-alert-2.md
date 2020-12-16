#### Parser Content
```Java
{
Name = s-symantec-security-alert-2
  DataType = "alert"
  Conditions = [ """vendor_product="Symantec Endpoint Protection"""", """symantec_ep_risk""" ]
  Fields = ${SymantecParserTemplates.s-symantec-alert.Fields}[
    """orig_host=({src_host}.*?),\s\w+=""",
    """orig_source="({process}[^"]+\\({process_name}[^"]+))"""",
  ]
}
```