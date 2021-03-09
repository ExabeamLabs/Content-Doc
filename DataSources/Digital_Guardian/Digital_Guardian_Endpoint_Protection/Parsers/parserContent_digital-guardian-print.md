#### Parser Content
```Java
{
Name = digital-guardian-print
  Product = Digital Guardian Endpoint Protection
  DataType = "print-activity"
  Conditions = [ """ Agent_Local_Time="""", """ User_Name="""", """ Operation="22"""" ]
  Fields = ${DGParserTemplates.digital-guardian-activity.Fields}[
  ]
}
```