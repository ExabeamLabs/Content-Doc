#### Parser Content
```Java
{
Name = auditbeat-ssh-login-2
  DataType = "ssh-login"
  Conditions = ["""logstash-auditbeat""", """"process"""",  """"op":"pubkey_auth"""", """ssh"""]
}
```