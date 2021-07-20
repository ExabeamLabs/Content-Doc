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