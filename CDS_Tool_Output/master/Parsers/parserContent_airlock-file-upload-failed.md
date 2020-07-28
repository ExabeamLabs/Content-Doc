#### Parser Content
```Java
{
Name = airlock-file-upload-failed
  DataType = "file-operations"
  Conditions = [ """ Audit Log [""", """ event_type="""", """" time_taken="""", """" system_name="""", """"Upload Failed"""" ]
  Fields = ${AirlockTemplates.AirlockEvent.Fields}[
    """\sremarks="({failure_reason}[^"]+)"""",
  ]
}
```