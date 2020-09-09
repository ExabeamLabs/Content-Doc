#### Parser Content
```Java
{
Name = cef-atp-alert-8
  Conditions = [ """CEF""", """|Microsoft|Azure ATP|""", """|DirectoryServicesRoguePromotionSecurityAlert|""" ]
}

${MicrosoftParserTemplates.cef-atp-alert}{
  Name = cef-atp-alert-9
  Conditions = [ """CEF""", """|Microsoft|Azure ATP|""", """|DirectoryServicesRogueReplicationSecurityAlert|""" ]
}

${MicrosoftParserTemplates.cef-atp-alert}{
  Name = cef-atp-alert-11
  Conditions = [ """CEF""", """|Microsoft|Azure ATP|""", """|DnsRemoteCodeExecutionSecurityAlert|""" ]
}

${MicrosoftParserTemplates.cef-atp-alert}{
  Name = cef-atp-alert-12
  Conditions = [ """CEF""", """|Microsoft|Azure ATP|""", """|DnsSuspiciousCommunicationSecurityAlert|""" ]
}

${MicrosoftParserTemplates.cef-atp-alert}{
  Name = cef-atp-alert-13
  Conditions = [ """CEF""", """|Microsoft|Azure ATP|""", """|EncryptionDowngradeSecurityAlert|""" ]
}

${MicrosoftParserTemplates.cef-atp-alert}{
  Name = cef-atp-alert-14
  Conditions = [ """CEF""", """|Microsoft|Azure ATP|""", """|ForgedPacSecurityAlert|""" ]
}

${MicrosoftParserTemplates.cef-atp-alert}{
  Name = cef-atp-alert-15
  Conditions = [ """CEF""", """|Microsoft|Azure ATP|""", """|ForgedPrincipalSecurityAlert|""" ]
}

${MicrosoftParserTemplates.cef-atp-alert}{
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
    """"policyType":"({alert_type}[^"]+)"""
  ]
}
```