#### Parser Content
```Java
{
Name = auditbeat-unix-account-delete-2
  DataType = "unix-account-deleted"
  Conditions = ["""logstash-auditbeat""", """"process"""",  """"op":"delete-shadow-group""""]
}
```