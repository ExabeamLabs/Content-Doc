#### Parser Content
```Java
{
Name = ms-azure-eventhubs-login
  DataType = "app-login"
  Conditions = [ """eventHubsAzureRecord""", """Sign-in activity""" ]
  Fields = ${MSParserTemplates.ms-azure-eventhubs-activity.Fields} [
    """"{1,20}identity"{1,20}:"{1,20}({user_fullname}[^",]{1,2000})"{1,20}""",
    """"{1,20}identity"{1,20}:"{1,20}({user_lastname}[^",]{1,2000}),\s{0,100}({user_firstname}[^",\/]{1,2000})(\/[^"]{0,2000})?"""",
    """"{1,20}userId"{1,20}:"{1,20}({user_id}[^"]{1,2000})"{1,20}""",
    """"{1,20}appDisplayName"{1,20}:"{1,20}({app}[^"]{1,2000})"{1,20}""",
    """"{1,20}operatingSystem"{1,20}:"{1,20}({os}[^"]{1,2000})"{1,20}""",
    """"{1,20}browser"{1,20}:"{1,20}({browser}[^"]{1,2000})"{1,20}""",
    """"{1,20}location"{1,20}:(\{"{1,20}geoCoordinates"{1,20}:\{\}\}|({additional_info}\{.*?\}))"""
    """"{1,20}failureReason"{1,20}:"{1,20}({failure_reason}[^"]{1,2000})"{1,20}"""
  ]

ms-azure-eventhubs-activity = {
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = QRadar
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"{1,20}callerIpAddress"{1,20}:"{1,20}(<null>|({src_ip}[^"]{1,2000}))"{1,20}""",
    """"{1,20}initiatedBy.*?"{1,20}userPrincipalName"{1,20}:"{1,20}({user_email}[^@]{1,2000}@({email_domain}[^"]{1,2000}))"{1,20}"""
    """"{1,20}targetResources.*?"{1,20}displayName"{1,20}:"{1,20}({object}[^"]{1,2000}?)"{1,20}""",
    """"{1,20}targetResources.*?"{1,20}userPrincipalName"{1,20}:"{1,20}({object}[^"]{1,2000}?)"{1,20}"""
    """"{1,20}targetResources.*?"{1,20}displayName"{1,20}:"{1,20}.*?\.DisplayName"{1,20}.*?"{1,20}newValue"{1,20}:[\\"]{0,2000}(null|({target}[^"\\]{1,2000}))["\\]{0,2000}"""
    """"{1,20}time"{1,20}:"{1,20}({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{7}\w+)"{1,20}"""
    """"{1,20}operationName"{1,20}:"{1,20}({activity}[^"]{1,2000})"{1,20}""",
    """"{1,20}result"{1,20}:"{1,20}({outcome}[^"]{1,2000})"{1,20}""",
    """({app}eventHubsAzureRecord)""" 
  
}
```