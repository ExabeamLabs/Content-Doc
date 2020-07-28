#### Parser Content
```Java
{
Name = auditbeat-ssh-login
  DataType = "ssh-login"
  Conditions = ["""logstash-auditbeat""", """"process"""", """"op":"PAM:authentication""""]
}
```