#### Parser Content
```Java
{
Name = cef-atp-alert-16
  Conditions = [ """CEF""", """|Microsoft|Azure ATP|""", """|GoldenTicketEncryptionDowngradeSecurityAlert|""" ]
}

${MicrosoftParserTemplates.cef-atp-alert}{
  Name = cef-atp-alert-17
  Conditions = [ """CEF""", """|Microsoft|Azure ATP|""", """|GoldenTicketSecurityAlert|""" ]
}

${MicrosoftParserTemplates.cef-atp-alert}{
  Name = cef-atp-alert-18
  Conditions = [ """CEF""", """|Microsoft|Azure ATP|""", """|GoldenTicketSizeAnomalySecurityAlert|""" ]
}

${MicrosoftParserTemplates.cef-atp-alert}{
  Name = cef-atp-alert-19
  Conditions = [ """CEF""", """|Microsoft|Azure ATP|""", """|HoneytokenActivitySecurityAlert|""" ]
}

${MicrosoftParserTemplates.cef-atp-alert}{
  Name = cef-atp-alert-20
  Conditions = [ """CEF""", """|Microsoft|Azure ATP|""", """|LdapBruteForceSecurityAlert|""" ]
}

${MicrosoftParserTemplates.cef-atp-alert}{
  Name = cef-atp-alert-21
  Conditions = [ """CEF""", """|Microsoft|Azure ATP|""", """|MaliciousServiceCreationSecurityAlert|""" ]
}

${MicrosoftParserTemplates.cef-atp-alert}{
  Name = cef-atp-alert-22
  Conditions = [ """CEF""", """|Microsoft|Azure ATP|""", """|PassTheHashSecurityAlert|""" ]
}

${MicrosoftParserTemplates.cef-atp-alert}{
  Name = cef-atp-alert-23
  Conditions = [ """CEF""", """|Microsoft|Azure ATP|""", """|PassTheTicketSecurityAlert|""" ]
}

${MicrosoftParserTemplates.cef-atp-alert}{
  Name = cef-atp-alert-24
  Conditions = [ """CEF""", """|Microsoft|Azure ATP|""", """|RemoteExecutionSecurityAlert|""" ]
}

${MicrosoftParserTemplates.cef-atp-alert}{
  Name = cef-atp-alert-25
  Conditions = [ """CEF""", """|Microsoft|Azure ATP|""", """|RetrieveDataProtectionBackupKeySecurityAlert|""" ]
}

${MicrosoftParserTemplates.cef-atp-alert}{
  Name = cef-atp-alert-26
  Conditions = [ """CEF""", """|Microsoft|Azure ATP|""", """|SamrReconnaissanceSecurityAlert|""" ]
}

${MicrosoftParserTemplates.cef-atp-alert}{
  Name = cef-atp-alert-27
  Conditions = [ """CEF""", """|Microsoft|Azure ATP|""", """|SmbDataExfiltrationSecurityAlert|""" ]
}

${MicrosoftParserTemplates.cef-defender-atp}{
  Name = cef-defender-atp-network-con
  DataType = "network-connection"
  Conditions = ["""CEF""", """SkyFormation Cloud Apps Security""", """requestClientApplication=""", """AdvancedHunting-DeviceNetworkEvents"""]
  Fields = ${MicrosoftParserTemplates.cef-defender-atp.Fields} [
     """RemoteUrl":\s*"(|(\w+:\/*)?({web_domain}([^"]+\.)?({top_domain}[^"]+\.[^"]+)?))"""",
     """DeviceName":\s*"({dest_host}[^"]+)""",
     """"InitiatingProcessFolderPath":\s*"({process}({directory}[^"]*?[\\\/]+)?({process_name}[^"\\\/]+?))""""
     """({category}AdvancedHunting-DeviceNetworkEvents)"""
  ]
}

${MicrosoftParserTemplates.cef-defender-atp}{
  Name = cef-defender-atp-alert
  DataType = "alert"
  Conditions = ["""CEF""", """SkyFormation Cloud Apps Security""", """requestClientApplication=Defender ATP""", """AdvancedHunting-DeviceAlertEvents"""]
  Fields = ${MicrosoftParserTemplates.cef-defender-atp.Fields} [ 
     """Category":\s*"({alert_type}[^"]+)""",
     """Title":\s*"({alert_name}[^"]+)""",
     """FileName":\s*"({process_name}[^"]+)""",
     """Severity":\s*"({alert_severity}[^"]+)""",
     """AlertId":\s*"({alert_id}[^"]+)"""
     """DeviceName":\s*"({src_host}[^"]+)""",
     """MD5":"({md5}[^"]+)""",

  ] 
}

${MicrosoftParserTemplates.cef-defender-atp}{
  Name = cef-defender-atp-process
  DataType = "process-created"
  Conditions = ["""CEF""", """SkyFormation Cloud Apps Security""", """requestClientApplication=""", """AdvancedHunting-DeviceProcessEvents"""]
  Fields = ${MicrosoftParserTemplates.cef-defender-atp.Fields} [
     """ProcessId":({pid}\d+)""",
     """InitiatingProcessFileName":\s*"({parent_process}[^"]+)""",
     """"FileName":\s*"({process_name}[^"]+)""",
     """DeviceName":\s*"({dest_host}[^"]+)""",
     """ProcessCommandLine":\s*"({command_line}[^"]+)\s*""""
     """MD5":"({md5}[^"]+)""",
 ]
}

${MicrosoftParserTemplates.cef-defender-atp}{
  Name = cef-defender-atp-file
  DataType = "file-operations"
  Conditions = ["""CEF""", """SkyFormation Cloud Apps Security""", """requestClientApplication=""", """AdvancedHunting-DeviceFileEvents"""]
  Fields = ${MicrosoftParserTemplates.cef-defender-atp.Fields} [
     """"FileName"+:\s*"+({process_name}[^"]+)""",
     """"FolderPath"+:\s*"+({file_path}({file_parent}[^"]*?[\\\/]+)?({file_name}[^"\\\/]+?(\.({file_ext}\w+))?))"""",
     """DeviceName"+:\s*"+({dest_host}[^"]+)""",
     """MD5"+:"+({md5}[^"]+)""",
]
}

${MicrosoftParserTemplates.cef-defender-atp}{
  Name = cef-defender-atp-logon
  DataType = "app-login"
  Conditions = ["""CEF""", """SkyFormation Cloud Apps Security""", """requestClientApplication=""", """AdvancedHunting-DeviceLogonEvents"""]
  Fields = ${MicrosoftParserTemplates.cef-defender-atp.Fields} [
    """"LogonId"+:({logon_id}\d)""",
    """"DeviceName"+:\s*"+({dest_host}[^"]+)""",
    """"ActionType"+:\s*"+({outcome}.+?)","[^\\"]+":""""
  ]
}

${MicrosoftParserTemplates.defender-atp-events}{
  Name = defender-atp-process
  DataType = "process-created"
  Conditions = [  """"Type":"AdvancedHuntingDeviceEvents_CL""" ,"""TimeGenerated""", """TenantId""" ]
  Fields = ${MicrosoftParserTemplates.defender-atp-events.Fields}[
    """"FileName"+:\s*"+({process_name}[^"]+)""",
    """"FolderPath"+:\s*"+({file_path}({file_parent}[^"]*?[\\\/]+)?({file_name}[^"\\\/]+?(\.({file_ext}\w+))?))"""",
]
}

${MicrosoftParserTemplates.defender-atp-events}{
  Name = defender-atp-file-events
  DataType = "file-operations"
  Conditions = [  """"Type":"AdvancedHuntingDeviceFileEvents_CL""" ,"""TimeGenerated""", """TenantId""" ]
  Fields = ${MicrosoftParserTemplates.defender-atp-events.Fields}[
]
  DupFields = ["outcome->accesses"]
}
 
${MicrosoftParserTemplates.defender-atp-events}{
  Name = defender-atp-logon
  DataType = "app-login"
  Conditions = [  """"Type":"AdvancedHuntingDeviceLogonEvents_CL""" , """TimeGenerated""", """TenantId""" ]
  Fields = ${MicrosoftParserTemplates.defender-atp-events.Fields}[
]
}

${MicrosoftParserTemplates.defender-atp-events}{
  Name = defender-atp-process-2
  DataType = "process-created"
  Conditions = [  """"Type":"AdvancedHuntingDeviceProcessEvents_CL""", """TimeGenerated""", """TenantId""" ]
  Fields = ${MicrosoftParserTemplates.defender-atp-events.Fields}[
]
}

${MicrosoftParserTemplates.defender-atp-events}{
  Name = defender-atp-network
  DataType = "network-connection"
  Conditions = [  """"AdvancedHunting-DeviceNetworkEvents"""" , """TimeGenerated""", """TenantId"""]
  Fields = ${MicrosoftParserTemplates.defender-atp-events.Fields}[
]
}

${CASParserTemplates.cas-template}{
  Name = cas-login-failed
  DataType = "failed-app-login"
  Conditions = ["""ACTION: AUTHENTICATION_FAILED""", """ACTION: """, """WHO: """, """WHEN: """, """CLIENT IP ADDRESS: """, """SERVER IP ADDRESS: """]
  Fields = ${CASParserTemplates.cas-template.Fields} [
  ]
}

${CASParserTemplates.cas-template}{
  Name = cas-login-success
  DataType = "app-login"
  Conditions = ["""ACTION: AUTHENTICATION_SUCCESS""", """ACTION: """, """WHO: """, """WHEN: """, """CLIENT IP ADDRESS: """, """SERVER IP ADDRESS: """]
  Fields = ${CASParserTemplates.cas-template.Fields} [
  ]
}

${CASParserTemplates.cas-template}{
  Name = cas-app-activity
  DataType = "app-activity"
  Conditions = ["""ACTION: """, """WHO: """, """WHEN: """, """CLIENT IP ADDRESS: """, """SERVER IP ADDRESS: """]
  Fields = ${CASParserTemplates.cas-template.Fields} [
  ]
}

{
  Name = cef-cas-security-alert
  Vendor = Microsoft
  Product = Microsoft CAS
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """dproc=mcas-alerts""", """"description":"""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """\Wshost=(|(src_host).+?)(\s+\w+=|\s*$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wsuser=(|({user_email}[^@=]+?@[^@=]+)|({user}.+?))(\s+\w+=|\s*$)""",
    """"timestamp":({time}\d+)""",
    """"description":"\s*({additional_info}[^"]+?)\s*"""",
    """"title":"({alert_name}[^"]+)""",
    """"URL":"({malware_url}[^"]+)""",
    """"severityValue":({alert_severity}\d+)""",
    """"_id":"({alert_id}[^"]+)""",
    """"policyType":"({alert_type}[^"]+)""",
    """"threatScore"+:({threat_score}\d+)""",
    """shost=({country_code}.+?)\s\w+=""",
    """\srequestClientApplication=({app}.+?)\s*\w+="""
  ]
}
```