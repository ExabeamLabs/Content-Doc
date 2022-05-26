#### Parser Content
```Java
{
Name = sailpoint-app-activity-3
  DataType = "app-activity"
  Conditions = [ """"ATTRIBUTE_NAME""", """"ACCOUNT_NAME""", """"APPLICATION""", """"OWNER""", """"ACTION""", """"TARGET""", """"SOURCE""" ]

sailpoint-iiq-events = {
  Vendor = Sailpoint
  Product = SailPoint IIQ
  Lms = Syslog
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,3}Z)"""",
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """"ACCOUNT_NAME\\?":\\?"(({account_dn}(((CN|cn|uid)=[^"]{1,2000}?),)?(({account_ou}(OU|ou)[^"]{1,2000}?)?(DC|dc)=[\w-]{1,2000}))|({account_id}[^"]{1,2000}?)\\?")""",
    """"TARGET\\?":\\?"(({user_email}[^@"]{1,2000}@[^"]{1,2000}?)|({user}[^"\s]{1,2000}?))\\?"""",
    """"SOURCE\\?":\\?"(({user_email}[^@"]{1,2000}@[^"]{1,2000}?)|({user}[^"\s]{1,2000}?))\\?"""",
    """"APPLICATION\\?":\\?"({app}[^"]{1,2000}?)\\?"""",
    """"ACTION\\?":\\?"({activity}[^"]{1,2000}?)\\?""""
  
}
```