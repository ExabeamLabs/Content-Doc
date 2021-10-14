#### Parser Content
```Java
{
Name = azure-app-logon
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "app-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"operationName"""", """"Sign-in activity"""", """"conditionalAccessStatus"""", """"tokenIssuerType"""", """":""""]
  Fields = [
    """exabeam_host=([^=@]{1,2000}@\s{0,100})?({host}\S+)""",
    """"time"{1,20}:"{1,20}({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})""",
    """"callerIpAddress"{1,20}:"{1,20}({src_ip}[A-Fa-f:\d.]{1,2000})"""",
    """"identity"{1,20}:"{1,20}(({user_id}\w+-\w+-\w+-\w+-\w+)|({user_fullname}({user_lastname}[^",\s]{1,2000})\s{0,100},?\s{0,100}({user_firstname}[^",]{1,2000})))"""",
    """"userPrincipalName"{1,20}:"{1,20}({user_email}[^"\s@]{1,2000}@[^"\s@]{1,2000})"""",
    """"conditionalAccessStatus"{1,20}:"{1,20}({outcome}[^"]{1,2000})"""",
    """"tokenIssuerType"{1,20}:"{1,20}({app}[^"]{1,2000})"""",
    """"failureReason"{1,20}:"{1,20}({failure_reason}[^"]{1,2000}?)(\.)?"""",
    """"userAgent"{1,20}:"{1,20}({user_agent}[^"]{1,2000})\s{0,100}"""",
    """"operationName"{1,20}:"{1,20}({event_name}[^",]{1,2000})""",
    """"authenticationMethod":"({auth_method}[^"]{1,2000})"""",
    """"additionalDetails":"({additional_info}[^"]{1,2000})"""",
    """"countryOrRegion":"({country_code}[^"]{1,2000})"""",
    """"appDisplayName":"({resource}[^"]{1,2000})"""",
    """"resultType":"({error_code}\d{1,100})"""",
    """deviceDetail":\{[^\}]{1,2000}?displayName":"({src_host}[^"]{1,2000})"""",
    """userId":"({user_id}[^"]{1,2000})""""
  ]
}
```