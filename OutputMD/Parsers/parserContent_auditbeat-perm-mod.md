#### Parser Content
```Java
{
Name = auditbeat-perm-mod
  DataType = "file-permission-change"
  Conditions = ["""logstash-auditbeat""", """"process"""", """"tags":["perm_mod"""", """changed-file-permissions-of"""]
}
```