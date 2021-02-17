#### Parser Content
```Java
{
Name = digital-guardian-file-save-as
  Product = Digital Guardian Endpoint Protection
  DataType = "file-write"
  Conditions = [ """ Agent_Local_Time="""", """ User_Name="""", """ Operation="7"""" ]
  Fields = ${DGParserTemplates.digital-guardian-activity.Fields}[
  ]
}
```