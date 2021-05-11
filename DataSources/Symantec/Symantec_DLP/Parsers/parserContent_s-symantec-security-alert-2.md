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
s-symantec-alert = {
    Vendor = Symantec
    Product = Symantec Endpoint Protection
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Fields = [
      """exabeam_host=({host}[^\s]+)""",
      """\sEnd_Time="({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
      """\sHost_Name=({host}[^,]+?)\s{0,100}(,|$)""",
      """\sdest=({dest_host}[^,]+?)\s{0,100}(,|$)""",
      """\suser=({user}[^,]+?)\s{0,100}(,|$)""",
      """\saction=({action}[^,]+?)\s{0,100}(,|$)""",
      """\ssignature="({alert_name}[^"]+)""",
      """\seventtype="?({alert_type}[^",]+)""",
      """\sseverity=({alert_severity}[^,]+?)\s{0,100}(,|$)""",
      """\sEvent_Description="({additional_info}[^"]+)""",
      """\sdest_port=({dest_port}\d{1,100})""", 
    ]

```