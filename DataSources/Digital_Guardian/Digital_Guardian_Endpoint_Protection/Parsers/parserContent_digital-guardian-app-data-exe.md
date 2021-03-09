#### Parser Content
```Java
{
Name = digital-guardian-app-data-exe
  Product = Digital Guardian Endpoint Protection
  DataType = "app-activity"
  Conditions = [ """ Agent_Local_Time="""", """ User_Name="""", """ Operation="21"""" ]
  Fields = ${DGParserTemplates.digital-guardian-activity.Fields}[
  ]
}
```