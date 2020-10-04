#### Parser Content
```Java
{
Name = cef-defender-atp-member-removed
  DataType = "windows-member-removed"
  Conditions = ["""CEF:""", """|SkyFormation Cloud Apps Security|""", """requestClientApplication=""", """AdvancedHunting-DeviceEvents""","""UserAccountRemovedFromLocalGroup"""]
  Fields = ${MicrosoftParserTemplates.cef-defender-atp.Fields}[
  """"LogonId":(null|"({logon_id}[^"]+))""",
  """AccountDomain":"({group_domain}[^"]+)"""
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