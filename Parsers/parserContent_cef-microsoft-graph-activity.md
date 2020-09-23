#### Parser Content
```Java
{
Name = cef-microsoft-graph-activity
 Vendor = Microsoft
 Product = Microsoft Office 365
 DataType = "failed-app-login"
 Lms = Direct
 TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
 Conditions = [ """appDisplayName":""", """"src-endpoint":"Graph Sign-In logs"""","""failureReason":""", """event-name":"login-failed""" ]
 Fields =[
   """"+time"+:"+({time}[^"]+)""",
   """({time}\d+-\d+-\d+T\d+:\d+:\d+.\d+Z)\s+({host}[^\s]+)\s+Skyformation""",
   """"+event-name"+:"+({event_name}[^"]+)""",
   """"+userDisplayName"+:"+({user_fullname}[^"]+)""",
   """"+userPrincipalName"+:"+({user_email}[^"]+)""",
   """"+userId"+:"+({user_id}[^"]+)""",
   """"+appDisplayName"+:"+({app}[^"]+)""",
   """"+ipAddress"+:"+({src_ip}[^"]+)""",
   """"+clientAppUsed"+:"+({object}[^"]+)""",
   """"+resourceDisplayName"+:"+({resource}[^"]+)""",
   """"+status"+.+?failureReason":"+({failure_reason}[^"]+)""",
   """"+additionalDetails":"+({additional_info}[^"]+)""",
   """"+deviceDetail".+?operatingSystem"+:"+({os}[^"]+)""",
   """"+location".+?city"+:"+({location_city}[^",]+)""",
   """"+location".+?state"+:"+({location_state}[^",]+)""",
   """"+location".+?countryOrRegion"+:"+({location_country}[^",]+)""",
   """"+application-action"+:"+({activity}[^"]+)""",
   """"+application-action".+?status"+.+?code":"+({outcome}[^"]+)""",
   """"+src-endpoint"+:"+({endpoint}[^"]+)""",
   """"+src-account-name"+:"+({account}[^"]+)""",
 ]
}

${MSParserTemplates.azure-event-hub}{
  Name = azure-event-hub-process-events
  DataType = "process-created"
  Conditions = ["""|beatname=eventhubbeat|""", """|device_type=eventhubbeat|""", """|subject=AdvancedHunting-DeviceProcessEvents|""", """vmid=""", """@timestamp""", """@metadata""", """"ActionType":"ProcessCreated""""]
  Fields = ${MSParserTemplates.azure-event-hub.Fields} [
  ]
}

${MSParserTemplates.azure-event-hub-network-events}{
  Name = azure-event-hub-network-connection
  DataType = "network-connection"
  Conditions = ["""|beatname=eventhubbeat|""", """|device_type=eventhubbeat|""", """|subject=AdvancedHunting-DeviceNetworkEvents|""", """vmid=""", """@timestamp""", """@metadata"""]
  Fields = ${MSParserTemplates.azure-event-hub-network-events.Fields} [
  ]
}

${MSParserTemplates.azure-event-hub-network-events}{
  Name = azure-event-hub-remote-logon
  DataType = "remote-logon"
  Conditions = ["""|beatname=eventhubbeat|""", """|device_type=eventhubbeat|""", """|subject=AdvancedHunting-DeviceEvents|""", """vmid=""", """@timestamp""", """@metadata""", """"ActionType":"RemoteDesktopConnection""""]
  Fields = ${MSParserTemplates.azure-event-hub-network-events.Fields} [
    """"LocalIP":"({src_ip}[A-Fa-f:\d.]+)""",
    """"LocalPort":({src_port}\d+)""",
    """"Protocol\\"+:\\"+({protocol}[^\\"]+)""",
  ]
}

${MSParserTemplates.azure-event-hub}{
  Name = azure-event-hub-file-events
  DataType = "file-operations"
  Conditions = ["""|beatname=eventhubbeat|""", """|device_type=eventhubbeat|""", """|subject=AdvancedHunting-DeviceFileEvents|""", """vmid=""", """@timestamp""", """@metadata""", """"ActionType":"""]
  Fields = ${MSParserTemplates.azure-event-hub.Fields} [
    """"FolderPath":"({file_path}({file_parent}(?:[^";]+)?[\\\/;])?({file_name}[^\\\/";]+?(\.({file_ext}[^\\\/\.;"]+))))""",
  ]
}

${MSParserTemplates.azure-event-hub}{
  Name = azure-event-hub-process-events-1
  DataType = "process-created"
  Conditions = ["""|beatname=eventhubbeat|""", """|device_type=eventhubbeat|""", """|subject=AdvancedHunting-DeviceEvents|""", """vmid=""", """@timestamp""", """@metadata""", """"ActionType":"PowerShellCommand""""]
  Fields = ${MSParserTemplates.azure-event-hub.Fields} [
  ]
}

${MSParserTemplates.azure-event-hub}{
  Name = azure-event-hub-file-read
  DataType = "file-read"
  Conditions = ["""|beatname=eventhubbeat|""", """|device_type=eventhubbeat|""", """|subject=AdvancedHunting-DeviceEvents|""", """vmid=""", """@timestamp""", """@metadata""", """"ActionType":"ReadProcessMemoryApiCall""""]
  Fields = ${MSParserTemplates.azure-event-hub.Fields} [
    """"FolderPath":"({file_path}({file_parent}(?:[^";]+)?[\\\/;])?({file_name}[^\\\/";]+?(\.({file_ext}[^\\\/\.;"]+))))""",
    """({accesses}ReadProcessMemoryApiCall)""",
  ]
}

${MSParserTemplates.azure-event-hub}{
  Name = azure-event-hub-member-added
  DataType = "member-added"
  Conditions = ["""|beatname=eventhubbeat|""", """|device_type=eventhubbeat|""", """|subject=AdvancedHunting-DeviceEvents|""", """vmid=""", """@timestamp""", """@metadata""", """"ActionType":"UserAccountAddedToLocalGroup""""]
  Fields = ${MSParserTemplates.azure-event-hub.Fields} [
    """"AccountName"+:"+({group_name}[^"]+)""",
    """"AccountDomain"+:"+({group_domain}[^"]+)""",
    """"AccountSid"+:"+({user_sid}[^"]+)""",
    """"MemberSid\\"+:\\"+({account_id}[^"]+)""", 
  ]
}

${MSParserTemplates.azure-event-hub}{
  Name = azure-event-hub-member-removed
  DataType = "member-removed"
  Conditions = ["""|beatname=eventhubbeat|""", """|device_type=eventhubbeat|""", """|subject=AdvancedHunting-DeviceEvents|""", """vmid=""", """@timestamp""", """@metadata""", """"ActionType":"UserAccountRemovedFromLocalGroup""""]
  Fields = ${MSParserTemplates.azure-event-hub.Fields} [
    """"AccountName"+:"+({group_name}[^"]+)""",
    """"AccountDomain"+:"+({group_domain}[^"]+)""",
    """"AccountSid"+:"+({user_sid}[^"]+)""",
    """"MemberSid\\"+:\\"+({account_id}[^"]+)""",
  ]
}

${MSParserTemplates.azure-event-hub}{
  Name = azure-event-hub-usb-insert
  DataType = "usb-insert"
  Conditions = ["""|beatname=eventhubbeat|""", """|device_type=eventhubbeat|""", """|subject=AdvancedHunting-DeviceEvents|""", """vmid=""", """@timestamp""", """@metadata""", """"ActionType":"UsbDriveMount""""]
  Fields = ${MSParserTemplates.azure-event-hub.Fields} [
     """SerialNumber\\"+:\\"+({device_id}\d+)"""
  ]
}

${MSParserTemplates.azure-event-hub}{
  Name = azure-event-hub-usb-activity
  DataType = "usb-activity"
  Conditions = ["""|beatname=eventhubbeat|""", """|device_type=eventhubbeat|""", """|subject=AdvancedHunting-DeviceEvents|""", """vmid=""", """@timestamp""", """@metadata""", """"ActionType":"UsbDriveUnmount""""]
  Fields = ${MSParserTemplates.azure-event-hub.Fields} [
     """SerialNumber\\"+:\\"+({device_id}\d+)"""
  ]
}

{
  Name = o365-dlp-alert
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = QRadar
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """DlpRuleMatch""", """"From"""", """"RuleName"""", """"PolicyName"":"""" ]
  Fields =[
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """Host Name:\s*({host}[^\s\\]+)""",
    """({event_name}DlpRuleMatch)""",
    """"CreationTime"+:\s*"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"From"+:\s*"+({user_email}[^@]+?@.+?)"""",
    """"To"+:\s*\[({recipients}({recipient}[^,]+)[^\]]*)\],""",
    """"BCC"+:\s*\[({bcc}[^\]]+)""",
    """"CC"+:\s*\[({cc}[^\]]+)""",
    """"PolicyName"+:\s*"+({alert_type}.*?[^"])"""",
    """"Subject"+:\s*"+({subject}.+?)\s*"+,"+To"+:""",
    """"RuleName"+:\s*"+({alert_name}[^",]+)"""",
    """"Severity"+:\s*"+({alert_severity}[^"]+)"""",
    """"Actions"+:\s*\["+({action}[^"]+)"+\]""",
    """"RecipientCount"+:\s*({recipient_count}\d+)""",  
    """"IncidentId"+:\s*"+({alert_id}[^",]+)"""",
    """"Workload"+:\s*"+({app}[^",]+)"""
 ]
}

{
  Name=azure-fw-network-connection
  Vendor = Microsoft
  Product=Microsoft Azure
  Lms=Direct
  DataType="network-connection"
  TimeFormat="yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions=["""CEF:0""", """|Skyformation|""", """|Azure""", """|traffic-flow|""", """cat=network-traffic"""]
  Fields=[
     """act=({outcome}.+?)\s*cat=""",
     """cs5=({additional_info}[^\s]+)\s+""",
     """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:({dest_port}\d+)(:({dest_interface}[^\s:]+))?(:({dest_host}[^\s:]+))?)?""",
     """dpt=({dest_port}.+?)\s*dst=""",
     """\Wdproc=({event_name}({category}[^,;\=]+)[^\=]*?)\s+(\w+=|$)""", 
     """proto=({protocol}.+?)\s*requestClientApplication=""",
     """\Wcs2=(N\/A|({src_interface}.+?))\s*(\w+=|$)""",
     """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:({src_port}\d+)(:({src_interface}\S+))?)?""",
     """spt=({src_port}.+?)\s*src=""", 
     """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d+Z)\s({host}\S+)\sSkyformation""",
     """dvchost=(N\/A|({dest_host}.+?))\s+(\w+=|$)""",
     """cat=({category}.+?)\s+(\w+=|$)"""
  ]
 }

{
  Name = skyformation-security-alert
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Direct
  DataType = "security-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """|Skyformation|SkyFormation Cloud Apps Security|""", """cat=security-alert""", """|general-alert|""", """destinationServiceName=Azure""", """requestClientApplication=Azure"""]
  Fields = [
    """({time}\d+-\d+-\d+T\d+:\d+:\d+.\d+Z)\s+({host}[^\s]+)\s+Skyformation""",   
    """msg=({additional_info}.+?)\s+(\w+=|$)""",
    """flexString1=({activity}.+?)\s*\w+=""",
    """request=({outcome}.+?)\s*\w+=""",
    """"severity":"({alert_severity}[^"]+)""",
    """cs1=({alert_name}.+?)\s+\w+=""",
    """sourceServiceName=\s*({service}.+?)\s+\w+""",
    """suser=(Azure Security Center|({user}.+?))\s+\w+=""",
    """intent":"\[\\"({alert_type}[^\\"]+)""",
 ]
}

${MSParserTemplates.azure-ad-activity}{
  Name = azure-ad-member-added
  DataType = "member-added"
  Conditions = [ """Microsoft.aadiam""", """Add member to group""", """tenantId":""""]
  Fields = ${MSParserTemplates.azure-ad-activity.Fields} [
    """({event_name}Add member to group)""",
    """targetResources":.+?Group\.DisplayName.+?newValue":"\\*"({group_name}[^\\"]+)""",
    """targetResources":.+?id":"({account_id}[^",]+)"""
  ]
}

${MSParserTemplates.azure-ad-activity}{
  Name = azure-ad-account-password-change
  DataType = "password-change"
  Conditions = [ """Microsoft.aadiam""", """Change user password""", """tenantId":""""]
  Fields = ${MSParserTemplates.azure-ad-activity.Fields} [
    """({event_name}Change user password)""",
    """targetResources":.+?userPrincipalName":"({target_user}[^",]+)""",
    """targetResources":.+?id":"({user_sid}[^",]+)"""
  ]
}

${MSParserTemplates.azure-ad-activity}{
  Name = azure-ad-member-removed
  DataType = "member-removed"
  Conditions = [ """Microsoft.aadiam""", """Remove member from group""", """tenantId":""""]
  Fields = ${MSParserTemplates.azure-ad-activity.Fields} [
    """({event_name}Remove member from group)""",
    """targetResources":.+?Group\.DisplayName.+?newValue":"\\*"({group_name}[^\\"]+)""",
    """targetResources":.+?id":"({account_id}[^",]+)"""
  ]
}

${MSParserTemplates.azure-ad-activity}{
  Name = azure-ad-account-password-change-1
  DataType = "password-change"
  Conditions = [ """Microsoft.aadiam""", """Self-service password reset""", """tenantId":""""]
  Fields = ${MSParserTemplates.azure-ad-activity.Fields} [
    """({event_name}Self-service password reset)""",
    """targetResources":.+?userPrincipalName":"({target_user}[^",]+)""",
    """targetResources":.+?id":"({user_sid}[^",]+)"""
  ]
}

${MSParserTemplates.azure-ad-activity}{
  Name = azure-ad-app-login
  DataType = "app-login"
  Conditions = [ """Microsoft.aadiam""", """Sign-in activity""", """tenantId":""""]
  Fields = ${MSParserTemplates.azure-ad-activity.Fields} [
    """({event_name}Sign-in activity)""",
    """userPrincipalName":"({user_email}[^",]+)""",
    """userId":"({user_uid}[^",]+)""",
    """errorCode":({error_code}\d+)""",
    """Level":({alert_severity}\d+)""",
    """appDisplayName":"\s*({app}[^",]+)""",
    """deviceDetail.+?displayName":"({object}[^",]+)""",
    """browser":"({browser}[^",]+)""",
    """userAgent":"({user_agent}.+?)"?,\w+":""",
    """operatingSystem.+?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)"""
  ]
}

${MSParserTemplates.azure-ad-activity}{
  Name = azure-ad-account-unlocked
  DataType = "account-unlocked"
  Conditions = [ """Microsoft.aadiam""", """Unlock user account (self-service)""", """tenantId":""""]
  Fields = ${MSParserTemplates.azure-ad-activity.Fields} [
    """({event_name}Unlock user account)""",
    """targetResources":.+?userPrincipalName":"({target_user}[^",]+)""",
    """targetResources":.+?id":"({user_sid}[^",]+)"""
  ]
}

${MSParserTemplates.azure-ad-activity}{
  Name = azure-ad-account-disabled
  DataType = "account-disabled"
  Conditions = [ """Microsoft.aadiam""", """Disable account""", """tenantId":""""]
  Fields = ${MSParserTemplates.azure-ad-activity.Fields} [
    """({event_name}Disable account)""",
    """targetResources":.+?userPrincipalName":"({target_user}[^",]+)""",
    """targetResources":.+?id":"({user_sid}[^",]+)"""
  ]
}
{
  Name = azure-file-read
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Splunk
  DataType = "file-read"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """|resource-viewed|""","""|Skyformation|""","""destinationServiceName=Azure""" ]
  Fields = [
   """({time}\d+-\d+-\d+T\d+:\d+:\d+.\d+Z)""",
   """"ResourceProvider":"({object}[^"]+)""",
   """"ResourceId":"({file_path}({file_parent}(?:[^";]+)?[\/;])?({file_name}[^\/";]+))""""
   """"Resource":"({file_name}[^"]+)"""",
   """suser=((?i)anonymous|({user}[^\s]+))""",
   """devicePayloadId=.+\s+name\s+:\s+\[({host}[^\]]+)"""
   """fileType=({file_type}[^\s]+)""",
   """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
   """"ResultType":"({outcome}[^"]+)""",
   """requestClientApplication=({app}.+?)\s\w+=""",
   """"OperationName":"({event_name}[^"]+)"""",
   """({accesses}resource-viewed)"""
   """msg=({additional_info}.+?)\s+\w+="""
  ]
}

{
  Name = azure-file-write
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Splunk
  DataType = "file-write"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """|Skyformation|""", """|sk4-resource-created|""", """|SkyFormation Cloud Apps Security|""", """destinationServiceName=Azure""" ]
  Fields = [
   """({time}\d+-\d+-\d+T\d+:\d+:\d+.\d+Z)""",
   """"ResourceProvider":"({object}[^"]+)""",
   """"ResourceId":"({file_path}({file_parent}(?:[^";]+)?[\/;])?({file_name}[^\/";]+))""""
   """"Resource":"({file_name}[^"]+)"""",
   """suser=((?i)anonymous|({user}[^\s]+))""",
   """devicePayloadId=.+\s+name\s+:\s+\[({host}[^\]]+)"""
   """fileType=({file_type}[^\s]+)""",
   """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
   """"ResultType":"({outcome}[^"]+)""",
   """requestClientApplication=({app}.+?)\s\w+=""",
   """"OperationName":"({event_name}[^"]+)"""",
   """({accesses}resource-created)"""
   """msg=({additional_info}.+?)\s+\w+="""
  ]
}
{
  Name = azure-event-hub-app-service-audit-logs
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=Azure""","""Category":"AppServiceAuditLogs""" ]
  Fields = [
    """"time"+:"+({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{7}\w+)"""",
    """\s\d+-\d+-\d+T\d+:\d+:\d+\.\d+\w+\s({host}[^\s]+)"""
    """destinationServiceName=({app}[^\s]+)""",
    """"Category":"({category}[^"]+)""",
    """suser=(anonymous|({user}.+?))\s+\w+="""
    """"ResourceId":"({object}[^"]+)"""",
    """"OperationName":"({activity}[^"]+)""",
    """"User":"({user}[^"]+)"""",
    """"UserDisplayName":"({user_email}[^@]+@[^\.]+\.[^"]+)"""",
    """"UserAddress":"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"Protocol":"({protocol}[^"]+)"""",
    """\[Namespace:\s*({azure_event_hub_namespace}\S+) ; EventHub name:\s*({azure_event_hub_name}[\w-]+)"""
  ]
}
```