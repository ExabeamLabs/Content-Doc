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
    """exabeam_host=({host}[\w.\-]+)""",
    """({time}\d{8}T\d{6}Z)\|(|({request_binding}[^\|]+))\|[^\|]*\|(|({relying_party_id}[^\|]+))\|([^\|]*\|){4}(|({principal_name}[^\|]+))\|""",
    """({src_ip}[a-fA-F\d.:]+)\|\s{0,100}$""",
    """\d{8}T\d{6}Z\|([^\|]*\|){7}({user}(?!\d{1,100})[^\|]+)\|""",
  ]
  DupFields = [ "request_binding->action" ]
}
```