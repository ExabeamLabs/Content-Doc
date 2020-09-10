#### Parser Content
```Java
{
Name = auditbeat-account-switch  
  DataType = "unix-account-switch"
  Conditions = ["""logstash-auditbeat""", """"process"""", """"op":"PAM:session_open""""]
}
```