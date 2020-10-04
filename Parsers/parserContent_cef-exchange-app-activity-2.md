#### Parser Content
```Java
{
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

${MSParserTemplates.cef-azure-event-hub}{
  Name = cef-azure-event-hub-security
  DataType = "alert"
  Conditions = [""""category":"Security"""", """"eventName""""]
  Fields = ${MSParserTemplates.cef-azure-event-hub.Fields}[
    """compromisedEntity":"({user_upn}[^"]+)"""",
    """userName":"(({domain}[^\\"]+)\\+)?({user}[^"]+)"""",
    """clientIPAddress":"({src_ip}[^",]+)""",
    """severity":"({alert_severity}[^"]+)"""",
    """operationId":"({alert_id}[^"]+)"""",
    """category":"({azure_category}[^"]+)"""",
    """attackedResourceType":"({azure_resource_type}[^"]+)"""",
    """\Wext_properties_eventProperties_attackers_0_=({src_ip}[a-fA-F\d.:]+)""",
    """\Wext_properties_eventProperties_previousIPAddress=(|({last_known_ip}.+?))(\s+\w+=|\s*$)""",
    """eventName":"({alert_type}.+?[^\\])"""",
    """\Wext_properties_eventProperties_malwareName=(|({alert_type}.+?))(\s+\w+=|\s*$)""",
    """resultDescription":"({alert_name}.+?[^\\])"""",
    """detailDescription":"({additional_info}.+?[^\\])"""",
    """Namespace:\s*(|({azure_event_hub_namespace}[^\]]+?))\s*[\];]""",
    """EventHub name:\s*(|({azure_event_hub_name}[^\]]+?))\s*\]"""
  ]
}

${MSParserTemplates.cef-azure-event-hub}{
  Name = azure-event-hub-application-gateway-access-log
  DataType = "app-activity"
  Conditions = ["""ext_category=ApplicationGatewayAccessLog""" ]
  Fields = ${MSParserTemplates.cef-azure-event-hub.Fields}[
    """host":"({app}.+?[^\\])"""",
    """operationName":"({activity}.+?[^\\])"""",
    """originalHost":"(({src_ip}[A-Fa-f\d.:]+)|({src_host}.+?[^\\]))"""",
    """userAgent":"(-|({user_agent}[^"\\]+))\\*"""",
    """requestUri":"({request_uri}[^"]+)"""",
    """receivedBytes":"*({bytes_in}\d+)""",
    """sentBytes":"*({bytes_out}\d+)""",
    """\[Namespace:\s*({azure_event_hub_namespace}\S+) ; EventHub name:\s*({azure_event_hub_name}[\w-]+)""",
  ]
}
```