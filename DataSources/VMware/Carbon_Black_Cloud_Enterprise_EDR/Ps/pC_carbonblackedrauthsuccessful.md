#### Parser Content
```Java
{
Name = carbonblack-edr-auth-successful
  Vendor = VMware
  Product = Carbon Black Cloud Enterprise EDR
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"Login in successfully through SAML 2.0"""", """destinationServiceName =Carbon Black Cloud""", """"description":"""", """"loginName":"""" ]
  Fields = [
    """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,3}Z)""",
    """"description":"({event_name}[^"]{1,2000})"""",
    """"loginName":"({user_email}[^@"]{1,2000}@[^"\.]{1,2000}\.[^"]{1,2000})"""",
    """"orgName":"({domain}[^"]{1,2000})"""",
    """"clientIp":"({src_ip}[a-fA-F\d:\.]{1,2000})""""
  ]


}
```