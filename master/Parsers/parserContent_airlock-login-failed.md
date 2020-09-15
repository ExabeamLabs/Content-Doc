#### Parser Content
```Java
{
Name = airlock-login-failed
  DataType = "failed-app-login"
  Conditions = [ """ Audit Log [""", """ event_type="""", """" time_taken="""", """" system_name="""", """"Login Failed"""" ]
  Fields = ${AirlockTemplates.AirlockEvent.Fields}[
    """\sremarks="({failure_reason}[^"]+)"""", 
  ]
}
```