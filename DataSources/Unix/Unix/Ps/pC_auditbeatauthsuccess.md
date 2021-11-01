#### Parser Content
```Java
{
Name = auditbeat-auth-success
  DataType = "authentication-successful"
  Conditions = ["""logstash-auditbeat""", """"process"""",  """"op":"login"""", """authentication""", """success"""]
}
```