#### Parser Content
```Java
{
Name = azure-eventhubbeat-app-activity
  DataType = "app-activity"
  Conditions= [ """"category":"Device"""", """"operationName":"Update device"""", """"activityDisplayName"""" ]
  Fields = ${MSParserTemplates.ms-azure-eventhubs-activity.Fields}[
    """({category}Device)""",
    """"operationType":"({activity_type}[^",]{1,2000})""""
  ]

ms-azure-eventhubs-activity = {
  Vendor = Microsoft
  Product = Azure
  Lms = QRadar
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"{1,20}callerIpAddress"{1,20}:"{1,20}(<null>|({src_ip}[A-Fa-f\d:.]{1,2000}))"{1,20}""",
    """"{1,20}initiatedBy.*?"{1,20}userPrincipalName"{1,20}:"{1,20}({user_email}[^@]{1,2000}@({email_domain}[^"]{1,2000}))"{1,20}"""
    """"{1,20}targetResources.*?"{1,20}displayName"{1,20}:"{1,20}({object}[^"]{1,2000}?)"{1,20}""",
    """"{1,20}targetResources.*?"{1,20}userPrincipalName"{1,20}:"{1,20}({object}[^"]{1,2000}?)"{1,20}"""
    """"{1,20}targetResources.*?"{1,20}displayName"{1,20}:"{1,20}.*?\.DisplayName"{1,20}.*?"{1,20}newValue"{1,20}:[\\"]{0,2000}(null|({target}[^"\\]{1,2000}))["\\]{0,2000}"""
    """"{1,20}time"{1,20}:"{1,20}({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{7}\w+)"{1,20}"""
    """"{1,20}operationName"{1,20}:"{1,20}({activity}[^"]{1,2000})"{1,20}""",
    """"{1,20}result"{1,20}:"{1,20}({outcome}[^"]{1,2000})"{1,20}""",
    """({app}eventHubsAzureRecord)""",
    """({app}eventhubbeat_APL_Azure)""",
    """"app"{1,20}:\{[^\}]{0,2000}?displayName"{1,20}:"{1,20}({app}[^",]{1,2000})"""",
    """object=({object}[^\|=\s]{1,2000})(\||\s\w{1,2000}=)""" 
  
}
```