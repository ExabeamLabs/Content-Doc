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

{ 
  Name = azure-blobegress-json
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Direct
  DataType = "azure-metrics"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """metricName":"Egress"""", """ApiName":"GetBlob""" ]
  Fields = [
    """"{1,20}count"{1,20}:\s{0,100}({blob_count}[^",\s]{1,2000})""",
    """"{1,20}total"{1,20}:\s{0,100}({bytes_total}[^",\s]{1,2000})""",
    """"{1,20}minimum"{1,20}:\s{0,100}({min_blob_size}[^",\s]{1,2000})""",
    """"{1,20}maximum"{1,20}:\s{0,100}({max_blob_size}[^",\s]{1,2000})""",
    """"{1,20}resourceId"{1,20}:\s{0,100}"{1,20}({resource}[^"]{1,2000})"{1,20}""",
    """"{1,20}time"{1,20}:\s{0,200}"{1,20}(\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}.\d{1,100}Z?)"{1,20}""",
    """"{1,20}metricName"{1,20}:\s{0,100}"{1,20}({metric_type}[^"]{1,2000})"{1,20}""",
    """"{1,20}AccountResourceId"{1,20}:\s{0,100}"{1,20}({storage_account_id}[^"]{1,2000}\/({storage_account}[^,"]{1,2000}))"{1,20}""",
    """"{1,20}ApiName"{1,20}:\s{0,100}"{1,20}({metric_name}[^"]{1,2000})"{1,20}""",
    """"{1,20}average"{1,20}:\s{0,100}({avg_blob_size}[^",\s]{1,2000})"""
  ]


}
```