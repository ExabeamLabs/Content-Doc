#### Parser Content
```Java
{
Name = s-symantec-process-alert
  DataType = "process-alert"
  Conditions = [ """vendor_product="Symantec Endpoint Protection"""", """signature="Rule:""" ]
  Fields = ${SymantecParserTemplates.s-symantec-alert.Fields}[
    """\sCaller_Process_Name="({process}({directory}[^"]*?)({process_name}[^"\\\/]+))""""
  ]
  DupFields = [ "alert_name->alert_type", "directory->process_directory" ]
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
    ]

```