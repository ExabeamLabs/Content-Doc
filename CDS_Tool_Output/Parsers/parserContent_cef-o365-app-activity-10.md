#### Parser Content
```Java
{
Name = cef-o365-app-activity-10
  Conditions = [ """|Microsoft|""", """|RemovedFromGroup|""", """eventId=""" ]
}
${MSParserTemplates.cef-o365-app-activity} {
  Name = cef-o365-app-activity-11
  Conditions = [ """|Microsoft|""", """|SearchQueryPerformed|""", """eventId=""" ]
}
${MSParserTemplates.cef-o365-app-activity} {
  Name = cef-o365-app-activity-12
  Conditions = [ """|Microsoft|""", """|SearchResultReturned|""", """eventId=""" ]
}
${MSParserTemplates.cef-o365-app-activity} {
  Name = cef-o365-app-activity-13
  Conditions = [ """|Microsoft|""", """|VideoRequested|""", """eventId=""" ]
}
${MSParserTemplates.cef-o365-app-activity} {
  Name = cef-o365-app-activity-14
  Conditions = [ """CEF:""", """|Microsoft Teams|""", """|TeamsSessionStarted|""" ]
}
${MSParserTemplates.cef-o365-app-activity} {
  Name = cef-o365-app-activity-15
  Conditions = [ """CEF:""", """|SharePoint Online|""", """|CompanyLinkUsed|""" ]
}
${MSParserTemplates.cef-o365-app-activity} {
  Name = cef-o365-app-activity-16
  Conditions = [ """CEF:""", """|SharePoint Online|""", """|ListColumnCreated|""" ]
}
${MSParserTemplates.cef-o365-app-activity} {
  Name = cef-o365-app-activity-17
  Conditions = [ """CEF:""", """|SharePoint Online|""", """|ListUpdated|""" ]
}
${MSParserTemplates.cef-o365-app-activity} {
  Name = cef-o365-app-activity-18
  Conditions = [ """CEF:""", """|SharePoint Online|""", """|DLPRuleMatch|""" ]
}
${MSParserTemplates.cef-o365-app-activity} {
  Name = cef-o365-app-activity-19
  Conditions = [ """CEF:""", """|Microsoft Teams|""", """|ChannelAdded|""" ]
}
${MSParserTemplates.cef-o365-app-activity} {
  Name = cef-o365-app-activity-20
  Conditions = [ """CEF:""", """|Microsoft Teams|""", """|MemberAdded|""" ]
}
${MSParserTemplates.cef-o365-app-activity} {
  Name = cef-o365-app-activity-21
  Conditions = [ """CEF:""", """|Microsoft Teams|""", """|MemberRemoved|""" ]
}
${MSParserTemplates.cef-o365-app-activity} {
  Name = cef-o365-app-activity-22
  Conditions = [ """CEF:""", """|Microsoft Teams|""", """|TabAdded|""" ]
}
${MSParserTemplates.cef-o365-app-activity} {
  Name = cef-o365-app-activity-23
  Conditions = [ """CEF:""", """|Microsoft Teams|""", """|TabUpdated|""" ]
}
${MSParserTemplates.cef-onedrive-app-activity-1} {
  Name = cef-onedrive-app-activity-1
  Conditions = [ """CEF:""", """|OneDrive|""", """|ListColumnUpdated|""" ]
}
${MSParserTemplates.cef-onedrive-app-activity-1} {
  Name = cef-onedrive-app-activity-2
  Conditions = [ """CEF:""", """|OneDrive|""", """|ListColumnCreated|""" ]
}
${MSParserTemplates.cef-onedrive-app-activity-1} {
  Name = cef-onedrive-app-activity-3
  Conditions = [ """CEF:""", """|OneDrive|""", """|ListUpdated|""" ]
}
${MSParserTemplates.cef-onedrive-app-activity-1} {
  Name = cef-onedrive-app-activity-4
  Conditions = [ """CEF:""", """|OneDrive|""", """|CompanyLinkUsed|""" ]
}
${MSParserTemplates.cef-onedrive-app-activity-1} {
  Name = cef-onedrive-app-activity-5
  Conditions = [ """CEF:""", """|OneDrive|""", """|ListCreated|""" ]
}
${MSParserTemplates.cef-onedrive-app-activity-1} {
  Name = cef-onedrive-app-activity-7
  Conditions = [ """CEF:""", """|OneDrive|""", """|FileSyncDownloadedPartial|""" ]
}
${MSParserTemplates.cef-exchange-app-activity-1} {
  Name = cef-exchange-app-activity-1
  Conditions = [ """CEF:""", """|Exchange Online|""", """|Create|""" ]
}
${MSParserTemplates.cef-exchange-app-activity-1} {
  Name = cef-exchange-app-activity-2
  Conditions = [ """CEF:""", """|Exchange Online|""", """|Update|""" ]
}
${MSParserTemplates.cef-exchange-app-activity-1} {
  Name = cef-exchange-app-activity-3
  Conditions = [ """CEF:""", """|Exchange Online|""", """|MoveToDeletedItems|""" ]
}
${MSParserTemplates.cef-exchange-app-activity-1} {
  Name = cef-exchange-app-activity-4
  Conditions = [ """CEF:""", """|Exchange Online|""", """|Set-User|""" ]
}
${MSParserTemplates.cef-exchange-app-activity-1} {
  Name = cef-exchange-app-activity-5
  Conditions = [ """CEF:""", """|Exchange Online|""", """|SoftDelete|""" ]
}
${MSParserTemplates.cef-exchange-app-activity-1} {
  Name = cef-exchange-app-activity-6
  Conditions = [ """CEF:""", """|Exchange Online|""", """|Set-Mailbox|""" ]
}
${MSParserTemplates.cef-exchange-app-activity-1} {
  Name = cef-exchange-app-activity-7
  Conditions = [ """CEF:""", """|Exchange Online|""", """|New-Mailbox|""" ]
}
${MSParserTemplates.cef-azure-app-activity-1} {
  Name = cef-azure-app-activity-1
  Conditions = [ """CEF:""", """|Azure""", """|Update group|""" ]
}
${MSParserTemplates.cef-azure-app-activity-1} {
  Name = cef-azure-app-activity-2
  Conditions = [ """CEF:""", """|Azure""", """|Update user|""" ]
}
${MSParserTemplates.cef-azure-app-activity-1} {
  Name = cef-azure-app-activity-3
  Conditions = [ """CEF:""", """|Azure""", """|Add user|""" ]
}
${MSParserTemplates.cef-azure-app-activity-1} {
  Name = cef-azure-app-activity-4
  Conditions = [ """CEF:""", """|Azure""", """|Update device|""" ]
}
${MSParserTemplates.cef-azure-app-activity-1} {
  Name = cef-azure-app-activity-5
  Conditions = [ """CEF:""", """|Azure""", """|Add member to group|""" ]
}
${MSParserTemplates.cef-o365-file-read} {
  Name = cef-o365-file-read-1
  Conditions = [ """|Microsoft|""", """|FileAccessed|""", """eventId=""" ]
}
${MSParserTemplates.cef-o365-file-read} {
  Name = cef-o365-file-read-2
  Conditions = [ """|Microsoft|""", """|FileAccessedExtended|""", """eventId=""" ]
}
${MSParserTemplates.cef-o365-file-read} {
  Name = cef-o365-file-read-3
  Conditions = [ """|Microsoft|""", """|FileCheckedOut|""", """eventId=""" ]
}
${MSParserTemplates.cef-o365-file-read} {
  Name = cef-o365-file-read-4
  Conditions = [ """|Microsoft|""", """|FileDownloaded|""", """eventId=""" ]
}
${MSParserTemplates.cef-o365-file-read} {
  Name = cef-o365-file-read-5
  Conditions = [ """|Microsoft|""", """|FilePreviewed|""", """eventId=""" ]
}
${MSParserTemplates.cef-o365-file-read} {
  Name = cef-o365-file-read-6
  Conditions = [ """|Microsoft|""", """|FileSyncDownloadedFull|""", """eventId=""" ]
}
${MSParserTemplates.cef-o365-file-read} {
  Name = cef-o365-file-read-7
  Conditions = [ """|Microsoft|""", """|PageViewed|""", """eventId=""" ]
}
${MSParserTemplates.cef-o365-file-read} {
  Name = cef-o365-file-read-8
  Conditions = [ """|Microsoft|""", """|PageViewedExtended|""", """eventId=""" ]
}
${MSParserTemplates.cef-o365-file-write} {
  Name = cef-o365-file-write-1
  Conditions = [ """|Microsoft|""", """|FileCheckedIn|""", """eventId=""" ]
}
${MSParserTemplates.cef-o365-file-write} {
  Name = cef-o365-file-write-2
  Conditions = [ """|Microsoft|""", """|FileModified|""", """eventId=""" ]
}
${MSParserTemplates.cef-o365-file-write} {
  Name = cef-o365-file-write-3
  Conditions = [ """|Microsoft|""", """|FileModifiedExtended|""", """eventId=""" ]
}
${MSParserTemplates.cef-o365-file-write} {
  Name = cef-o365-file-write-4
  Conditions = [ """|Microsoft|""", """|FileMoved|""", """eventId=""" ]
}
${MSParserTemplates.cef-o365-file-write} {
  Name = cef-o365-file-write-5
  Conditions = [ """|Microsoft|""", """|FileRenamed|""", """eventId=""" ]
}
${MSParserTemplates.cef-o365-file-write} {
  Name = cef-o365-file-write-6
  Conditions = [ """|Microsoft|""", """|FileSyncUploadedFull|""", """eventId=""" ]
}
${MSParserTemplates.cef-o365-file-write} {
  Name = cef-o365-file-write-7
  Conditions = [ """|Microsoft|""", """|FileUploaded|""", """eventId=""" ]
}
${MSParserTemplates.cef-o365-file-write} {
  Name = cef-o365-file-write-8
  Conditions = [ """|Microsoft|""", """|FolderCreated|""", """eventId=""" ]
}
${MSParserTemplates.cef-o365-file-write} {
  Name = cef-o365-file-write-9
  Conditions = [ """|Microsoft|""", """|FolderModified|""", """eventId=""" ]
}
${MSParserTemplates.cef-o365-file-write} {
  Name = cef-o365-file-write-10
  Conditions = [ """|Microsoft|""", """|FolderMoved|""", """eventId=""" ]
}
${MSParserTemplates.cef-o365-file-write} {
  Name = cef-o365-file-write-11
  Conditions = [ """|Microsoft|""", """|FolderRenamed|""", """eventId=""" ]
}
${MSParserTemplates.cef-o365-file-delete} {
  Name = cef-o365-file-delete-1
  Conditions = [ """|Microsoft|""", """|FileDeleted|""", """eventId=""" ]
}
${MSParserTemplates.cef-o365-file-delete} {
  Name = cef-o365-file-delete-2
  Conditions = [ """|Microsoft|""", """|FolderDeleted|""", """eventId=""" ]
}

${MSParserTemplates.o365-dlp-email-out} {
  Name = o365-dlp-email-out-1
  Conditions = [ """"Workload""", """"ClientProcessName"""", """"Subject"""", """"SendOnBehalf"""" ]
}

${MSParserTemplates.o365-dlp-email-out} {
  Name = o365-dlp-email-out-2
  Conditions = [ """"Workload""", """"ClientProcessName"""", """"Subject"""", """"SendAs"""" ]
}

{
  Name = o365-inbox-activity
  Vendor = Microsoft
  Product = Office 365
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = ["""destinationServiceName=Office 365""" , """SkyFormation Cloud Apps Security""" , """permissions-updated""", """"ResultStatus"""" , """Add-MailboxPermission"""]
  Fields = [
     """"CreationTime":\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
     """flexString1=({activity}[^\s]*)\srequest""",
     """\sby\s\[({user_email}[^\]]*)\]""",
     """ObjectId":"({resource}[^"]*)"""",
     """ResultStatus":"({outcome}[^"]*)"""",
     """Name":"AccessRights","Value":"({additional_info}[^"]*)"""",
     """destinationServiceName=(|({app}.+?))(\s+\w+=|\s*$)""",
     """ClientIP":"\[?({src_ip}[^"\]]*)?\]?(:\d{5})""",
     """duser=([^=]+\/)?({object}.+?)(\s+\w+=|\s*$)"""
   ]
}

${MSParserTemplates.cef-microsoft-app-activity} {
  Name = cef-microsoft-app-activity-1
  Product = Office 365
  Conditions= [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=Office 365""", """|authz-group-assigned|""" ]
}

${MSParserTemplates.cef-microsoft-app-activity} {
  Name = cef-microsoft-app-activity-2
  Product = Office 365
  Conditions= [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=Office 365""", """|authz-group-created|""" ]
}

${MSParserTemplates.cef-microsoft-app-activity} {
  Name = cef-microsoft-app-activity-3
  Product = Office 365
  Conditions= [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=Office 365""", """|authz-group-deleted|""" ]
}

${MSParserTemplates.cef-microsoft-app-activity} {
  Name = cef-microsoft-app-activity-4
  Product = Office 365
  Conditions= [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=Office 365""", """|authz-group-renamed|""" ]
}

${MSParserTemplates.cef-microsoft-app-activity} {
  Name = cef-microsoft-app-activity-5
  Product = Office 365
  Conditions= [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=Office 365""", """|authz-group-unassigned|""" ]
}
${MSParserTemplates.cef-microsoft-app-activity} {
  Name = cef-microsoft-app-activity-6
  Product = Office 365
  Conditions= [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=Office 365""", """|authz-group-updated|""" ]
}

${MSParserTemplates.cef-microsoft-app-activity} {
  Name = cef-microsoft-app-activity-7
  Product = Office 365
  Conditions= [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=Office 365""", """|integration-updated|""" ]
}

${MSParserTemplates.cef-microsoft-app-activity} {
  Name = cef-microsoft-app-activity-8
  Product = Office 365
  Conditions= [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=Office 365""", """|permissions-updated|""" ]
}

${MSParserTemplates.cef-microsoft-app-activity} {
  Name = cef-microsoft-app-activity-9
  Product = Office 365
  Conditions= [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=Office 365""", """|user-added|""" ]
}

${MSParserTemplates.cef-microsoft-app-activity} {
  Name = cef-microsoft-app-activity-10
  Product = Office 365
  Conditions= [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=Office 365""", """|user-deleted|""" ]
}

${MSParserTemplates.cef-microsoft-app-activity} {
  Name = cef-microsoft-app-activity-11
  Product = Office 365
  Conditions= [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=Office 365""", """|user-undeleted|""" ]
}

${MSParserTemplates.cef-microsoft-app-activity} {
  Name = cef-microsoft-app-activity-12
  Product = Office 365
  Conditions= [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=Office 365""", """|user-updated|""" ]
}

${MSParserTemplates.cef-microsoft-app-activity} {
  Name = cef-microsoft-app-activity-13
  Product = Microsoft Azure
  Conditions= [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=Azure""", """|resource-downloaded|""" ]
}

${MSParserTemplates.cef-microsoft-app-activity} {
  Name = cef-microsoft-app-activity-17
  Product = Office 365
  Conditions= [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=Office 365""", """|resource-content-updated|""" ]
}

${MSParserTemplates.cef-microsoft-app-activity} {
  Name = cef-microsoft-app-activity-18
  Product = Office 365
  Conditions= [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=Office 365""", """|resource-created|""" ]
}

${MSParserTemplates.cef-microsoft-app-activity} {
  Name = cef-microsoft-app-activity-19
  Product = Office 365
  Conditions= [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=Office 365""", """|resource-deleted|""" ]
  Fields = ${MSParserTemplates.cef-microsoft-app-activity.Fields} [
    """"ParentFolder":.+?"Path":"\\*({object}[^"]+)"""",
    """"DestFolder":.+?"Path":"\\*({object}[^"]+)"""",
  ]
}

{
  Name = o365-inbox-rules
  Vendor = Microsoft
  Product = Office 365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = ["""Operation":"Set-Mailbox""" , """DeliverToMailboxAndForward""" ]
  Fields = [
    """"CreationTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""",
    """Forward.+?Value":"(smtp:)?({target}[^"]+@({target_domain}[^"]+))""""
    """"ResultStatus":"({outcome}[^"]+)"""",
    """"ClientIP":"({src_ip}[^:]+):""",
    """({activity}DeliverToMailboxAndForward)"""",
    """msg=({additional_info}.+?)\srequest=""",
    """"Value":"(smtp:)?.+?@({target_domain}[^"]+)"""",
    """UserId":"({user_email}[^"\\\s@]+@({user_domain}[^"\\\s@]+))""",
    """({app}Office 365)"""
    """destinationServiceName=({app}.+?)\sdevice"""
  ]
}
```