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
    """orig_source="({process}[^"]{1,2000}\\({process_name}[^"]{1,2000}))"""", 
  ]
}
s-symantec-alert = {
    Vendor = Symantec
    Product = Symantec Endpoint Protection
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Fields = [
      """exabeam_host=({host}[^\s]{1,2000})""",
      """\sEnd_Time="({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
      """\sHost_Name=({host}[^,]{1,2000}?)\s{0,100}(,|$)""",
      """\sdest=({dest_host}[^,]{1,2000}?)\s{0,100}(,|$)""",
      """\suser=({user}[^,]{1,2000}?)\s{0,100}(,|$)""",
      """\saction=({action}[^,]{1,2000}?)\s{0,100}(,|$)""",
      """\ssignature="({alert_name}[^"]{1,2000})""",
      """\seventtype="?({alert_type}[^",]{1,2000})""",
      """\sseverity=({alert_severity}[^,]{1,2000}?)\s{0,100}(,|$)""",
      """\sEvent_Description="({additional_info}[^"]{1,2000})""",
      """\sdest_port=({dest_port}\d{1,100})""", 
    ]

```