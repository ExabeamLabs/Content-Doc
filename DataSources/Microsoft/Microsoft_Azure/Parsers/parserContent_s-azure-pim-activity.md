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
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """operationType": "({activity}[^"]+)""",
    """Microsoft.Authorization/roleDefinitions/({role}[^"\/]+)""",
    """activityDisplayName": "({additional_info}[^"]+)""",
    """"user": ["\w\s\{\:\-\,]+displayName": "({user_lastname}[^,":]+),\s*({user_firstname}[^"]+)""",
    """"user": ["\w\s\{\:\-\,]+userPrincipalName": "({user_email}.+?@[^"]+)""""
    """"user": \{.+?"id": "({user}[^"]+)""",
    """Microsoft.Authorization/roleDefinitions/({role}[^"\/\\]+)""",
    """Microsoft.Authorization/policyDefinitions/({policy}[^"\/\\]+)""",
    """"result": "({outcome}[^"]+)", "resultReason""""
 ]
}
```