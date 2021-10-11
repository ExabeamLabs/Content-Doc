#### Parser Content
```Java
{
Name = s-symantec-process-alert
  DataType = "process-alert"
  Conditions = [ """vendor_product="Symantec Endpoint Protection"""", """signature="Rule:""" ]
  Fields = ${SymantecParserTemplates.s-symantec-alert.Fields}[
    """\sCaller_Process_Name="({process}({directory}[^"]{0,2000}?)({process_name}[^"\\\/]{1,2000}))""""
    """\sCaller_Process_ID=({process_guid}\d{1,100})""",
  ]
  DupFields = [ "alert_name->alert_type", "directory->process_directory", "process_guid->pid" ]
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