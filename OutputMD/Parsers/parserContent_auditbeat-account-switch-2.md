#### Parser Content
```Java
{
Name = auditbeat-account-switch-2
  DataType = "unix-account-switch"
  Conditions = ["""logstash-auditbeat""", """"process"""", """priv_esc"""]
}
```