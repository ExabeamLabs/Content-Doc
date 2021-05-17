#### Parser Content
```Java
{
Name = fortiauthenticator-auth-successful
    Vendor = Fortinet
    Product = FortiAuthenticator
    Lms = Splunk
    DataType = "authentication-successful"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = [ """subcategory="Authentication"""", """action="Login"""" ]
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
      """exabeam_host=({host}[^\s]{1,2000})""",
      """exabeam_host=({dest_host}[^\s]{1,2000})""",
      """nas="({dest_host}[^"]{1,2000})"""",
      """user="({user}[^"]{1,2000})"""",
      """status="({outcome}[^"]{1,2000})"""",
      """action="({event_name}[^"]{1,2000})"""",
      """status="Success" ({additional_info}.+?)\s{0,100}$""",
      """status="Failed" ({failure_reason}.+?)( to .*?)?\s{0,100}$""",
    ]
  }
```