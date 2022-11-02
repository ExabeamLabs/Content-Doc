#### Parser Content
```Java
{
Name = o365-app-login
  Vendor = Microsoft
  Product = Office 365
  DataType = "app-login"
  Lms = Syslog
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """destinationServiceName =Snowflake""", """"appDisplayName":"""", """"result":"""", """"enforcedGrantControls":"""", """"resourceDisplayName":"""" ]
  Fields =[
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"createdDateTime":"({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d\.\d{1,3})"""",
    """"additionalDetails":"({event_name}[^"]{1,2000})"""",
    """"appDisplayName":"({app}[^"]{1,2000})"""",
    """"conditionalAccessStatus":"({outcome}[^"]{1,2000})"""",
    """"userDisplayName":"({user_fullname}[^"]{1,2000})"""",    
    """"userPrincipalName":"({user_email}[^@"]{1,2000}@[^"]{1,2000})"""",
    """"ipAddress":"({src_ip}[a-fA-F\d:.]{1,2000})"""",
    """"countryOrRegion":"({location_country}[^"]{1,2000})"""",
    """"city":"({location_city}[^"]{1,2000})"""",
    """"state":"({location_state}[^"]{1,2000})""""
  ]


}
```