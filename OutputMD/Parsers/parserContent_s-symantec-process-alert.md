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
```