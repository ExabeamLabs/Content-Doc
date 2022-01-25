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
    """@timestamp"{1,20}:"{1,20}({time}[^"]{1,2000})""",
    """"{1,20}hostname"{1,20}:"{1,20}({host}[^"]{1,2000})""",
    """"{1,20}SAML_Subject"{1,20}:"{1,20}({user_email}[^"]{1,2000})""",
    """"{1,20}Sensitive"{1,20}:"{1,20}({src_ip}[^"]{1,2000})""",
    """"{1,20}SSO_CALL"{1,20}:"{1,20}({auth_method}[^"]{1,2000})""",
    """"{1,20}Application"{1,20}:"{1,20}\s(\s|({service}[^"]{1,2000}))""",
    """"{1,20}Status"{1,20}:"{1,20}({outcome}[^"]{1,2000})""",
    """"{1,20}Sensitive_IAM_Server"{1,20}:"{1,20}({auth_server}[^"]{1,2000})"""
    """"{1,20}Protocol"{1,20}:"{1,20}({protocol}[^"]{1,2000})""",
    """"{1,20}Event"{1,20}:"{1,20}({activity}[^"]{1,2000})""",
    """"{1,20}ERROR"{1,20}:"{1,20}({failure_reason}[^"]{1,2000})""",
  ]
}
```