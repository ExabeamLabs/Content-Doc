#### Parser Content
```Java
{
Name = auditbeat-password-change
  DataType = "password-change"
  Conditions = ["""logstash-auditbeat""", """"process"""",  """"op":"password""""]
}
```