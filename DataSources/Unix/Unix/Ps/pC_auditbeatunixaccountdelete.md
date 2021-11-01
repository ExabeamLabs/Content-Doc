#### Parser Content
```Java
{
Name = auditbeat-unix-account-delete
  DataType = "unix-account-deleted"
  Conditions = ["""logstash-auditbeat""", """"process"""",  """"op":"PAM:delete-user""""]
}
```