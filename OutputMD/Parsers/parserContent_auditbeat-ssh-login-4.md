#### Parser Content
```Java
{
Name = auditbeat-ssh-login-4
  DataType = "ssh-login"
  Conditions = ["""logstash-auditbeat""", """"process"""", """"ssh"""", """user-login""", """was-authorized"""]
}
```