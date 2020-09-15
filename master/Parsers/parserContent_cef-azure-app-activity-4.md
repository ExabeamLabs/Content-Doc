#### Parser Content
```Java
{
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
  Conditions = ["""ext_category=Security""", """Azure Resource"""]
  Fields = ${MSParserTemplates.cef-azure-event-hub.Fields}[
    """\W(ext_properties_eventProperties_userName|ext_properties_eventProperties_accountsUsedOnFailedSignInToHostAttempts_1_)=(|({user_fullname}.+?))(\s+\w+=|\s*$)""",
    """\Wext_properties_eventProperties_compromisedEntity=(|({user_email}.+?))(\s+\w+=|\s*$)""",
    """\Wext_properties_eventProperties_clientIPAddress=({src_ip}[a-fA-F\d.:]+)""",
    """\Wext_properties_eventProperties_attackers_0_=({src_ip}[a-fA-F\d.:]+)""",
    """\Wext_properties_eventProperties_severity=(|({alert_severity}.+?))(\s+\w+=|\s*$)""",
    """\Wext_properties_operationId=(|({alert_id}.+?))(\s+\w+=|\s*$)""",
    """\Wext_properties_eventProperties_previousIPAddress=(|({last_known_ip}.+?))(\s+\w+=|\s*$)""",
    """eventName":"({alert_type}.*?[^\\])"""",
    """\Wext_properties_eventProperties_malwareName=(|({alert_type}.+?))(\s+\w+=|\s*$)""",
    """resultDescription":"({alert_name}.*?[^\\])"""",
    """detailDescription":"({additional_info}.*?[^\\])""""
  ]
}

${MSParserTemplates.cef-azure-event-hub}{
  Name = azure-event-hub-application-gateway-access-log
  DataType = "app-activity"
  Conditions = ["""ext_category=ApplicationGatewayAccessLog""" ]
  Fields = ${MSParserTemplates.cef-azure-event-hub.Fields}[
    """host":"({app}.*?[^\\])"""",
    """operationName":"({activity}.*?[^\\])"""",
    """originalHost":"({src_host}.*?[^\\])"""",
    """userAgent":"({user_agent}.*?[^\\])"""",
    """requestUri":"({request_uri}.*?[^\\])"""",
    """recievedBytes":"({bytes}\d+)""",
  ]
}
```