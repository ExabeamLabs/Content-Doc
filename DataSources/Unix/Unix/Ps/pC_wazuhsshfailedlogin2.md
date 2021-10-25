#### Parser Content
```Java
{
Name = wazuh-ssh-failed-login-2
  Product = Unix
  DataType = "authentication-failed"
  Conditions = [ """"decoder.name":"sshd"""", "Too many authentication failures for", """"type":"wazuh-alerts"""" ]
}
```