#### Parser Content
```Java
{
Name = shibboleth-auth-successful
  Vendor = Shibboleth
  Product = Shibboleth IdP
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyyMMdd'T'HHmmssZ"
  Conditions= [ """shibboleth""" , """:SAML:""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """({time}\d{8}T\d{6}Z)\|(|({request_binding}[^\|]{1,2000}))\|[^\|]{0,2000}\|(|({relying_party_id}[^\|]{1,2000}))\|([^\|]{0,2000}\|){4}(|({principal_name}[^\|]{1,2000}))\|""",
    """({src_ip}[a-fA-F\d.:]{1,2000})\|\s{0,100}$""",
    """\d{8}T\d{6}Z\|([^\|]{0,2000}\|){7}({user}(?!\d{1,100})[^\|]{1,2000})\|""",
  ]
  DupFields = [ "request_binding->action" ]


}
```