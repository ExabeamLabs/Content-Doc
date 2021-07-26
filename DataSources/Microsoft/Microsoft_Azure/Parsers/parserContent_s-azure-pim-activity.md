#### Parser Content
```Java
{
Name = s-azure-pim-activity
 Vendor = Microsoft
 Product = Microsoft Azure
 Lms = Splunk
 DataType = "cloud-admin-activity"
 TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
 Conditions = ["""activityDisplayName""" , """loggedByService": "PIM"""]
 Fields = [
    """({service}PIM)""",
    """activityDateTime": "({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """operationType": "({activity}[^"]{1,2000})""",
    """Microsoft.Authorization/roleDefinitions/({role}[^"\/]{1,2000})""",
    """activityDisplayName": "({additional_info}[^"]{1,2000})""",
    """"user": ["\w\s\{\:\-\,]{1,2000}displayName": "({user_lastname}[^,":]{1,2000}),\s{0,100}({user_firstname}[^"]{1,2000})""",
    """"user": ["\w\s\{\:\-\,]{1,2000}userPrincipalName": "({user_email}.+?@[^"]{1,2000})""""
    """"user": \{.+?"id": "({user}[^"]{1,2000})""",
    """Microsoft.Authorization/roleDefinitions/({role}[^"\/\\]{1,2000})""",
    """Microsoft.Authorization/policyDefinitions/({policy}[^"\/\\]{1,2000})""",
    """"result": "({outcome}[^"]{1,2000})", "resultReason""""
 ]
}
```