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
s-symantec-alert = {
    Vendor = Symantec
    Product = Symantec Endpoint Protection
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Fields = [
      """exabeam_host=({host}[^\s]+)""",
      """\sEnd_Time="({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
      """\sHost_Name=({host}[^,]+?)\s*(,|$)""",
      """\sdest=({dest_host}[^,]+?)\s*(,|$)""",
      """\suser=({user}[^,]+?)\s*(,|$)""",
      """\saction=({action}[^,]+?)\s*(,|$)""",
      """\ssignature="({alert_name}[^"]+)""",
      """\seventtype="?({alert_type}[^",]+)""",
      """\sseverity=({alert_severity}[^,]+?)\s*(,|$)""",
      """\sEvent_Description="({additional_info}[^"]+)""",
      """\sdest_port=({dest_port}\d+)""", 
    ]

```