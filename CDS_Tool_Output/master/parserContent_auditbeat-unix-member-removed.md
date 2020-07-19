#### Parser Content
```Java
{
Name = auditbeat-unix-member-removed
  DataType = "unix-member-removed"
  Conditions = ["""logstash-auditbeat""", """"process"""",  """"op":"deleting-user-from-shadow-group""""]
}
```