#### Parser Content
```Java
{
Name = auditbeat-file-access
  DataType = "object-access"
  Conditions = ["""logstash-auditbeat""", """"process"""", """"tags":["file_access""""]
}
```