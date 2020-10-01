#### Parser Content
```Java
{
Name = ping-federate-auth
  Vendor = Ping Identity
  Product = Ping Identity
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"SSO_CALL":""", """Sensitive":"""", """Status":""", """Transaction_ID":""""]
  Fields = [
    """@timestamp"+:"+({time}[^"]+)""",
    """"+hostname"+:"+({host}[^"]+)""",
    """"+SAML_Subject"+:"+({user_email}[^"]+)""",
    """"+Sensitive"+:"+({src_ip}[^"]+)""",
    """"+SSO_CALL"+:"+({auth_method}[^"]+)""",
    """"+Application"+:"+\s(\s|({service}[^"]+))""",
    """"+Status"+:"+({outcome}[^"]+)""",
    """"+Sensitive_IAM_Server"+:"+({auth_server}[^"]+)"""
    """"+Protocol"+:"+({protocol}[^"]+)""",
    """"+Event"+:"+({activity}[^"]+)""",
    """"+ERROR"+:"+({failure_reason}[^"]+)""",
  ]
}
```