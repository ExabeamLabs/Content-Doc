#### Parser Content
```Java
{
Name = stealthintercept-auth-successful
        DataType = "authentication-successful"
        Conditions = [ """ StealthINTERCEPT """, """ DistinguishedName =""", """ Login succeed """ ]

stealthintercept-auth = {
    Vendor = StealthBits
    Product = StealthIntercept
    Lms = Direct
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """exabeam_indexTime=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
      """"@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
      """({host}[\w\-.]{1,2000})\s{1,100}StealthINTERCEPT""",
      """\sStealthINTERCEPT\s{1,100}\-\s{1,100}({event_name}.+?)\s{1,100}\-\s{1,100}PolicyName""",
      """\sLogin failed .+? PolicyName ="({failure_reason}[^"]{1,2000})"""",
      """\sDomain="({domain}[^"]{1,2000})"""",
      """\sStealthINTERCEPT\s{1,100}\-\s{1,100}({auth_method}.+?)\s{1,100}Login""",
      """\sServer="(({domain}[^\\"]{1,2000})\\)?({dest_host}[^"]{1,2000})"""",
      """\sServerAddress="({dest_ip}[a-fA-F\d.:]{1,2000})"""",
      """\s(Perpetrator|ModifiedObject)="(({domain}[^\\"]{1,2000})\\)?({user}[^"]{1,2000})"""",
      """\sClientAddress="(unknown|({src_ip}[a-fA-F\d.:]{1,2000}))"""",
      """\sDistinguishedName ="({user_ou}[^"]{1,2000})"""",
    
}
```