#### Parser Content
```Java
{
Name = auditbeat-unix-account-created
  DataType = "unix-account-created"
  Conditions = ["""logstash-auditbeat""", """"process"""",  """"op":"add-user""""]
}
```