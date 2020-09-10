#### Parser Content
```Java
{
Name = cef-lyrix-badge-access
  Vendor = Lyrix
  Product = Lyrix
  Lms = Splunk
  DataType = "physical-access"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|SKUD|""", """cs2Label=DoorName""" ]
  Fields = [
    """CEF:([^\|]*\|){5}({outcome}[^\|]+)""",
    """\Wdvc=({host}[A-Fa-f:\d.]+)""",
    """\Wdvchost=({host}[\w\-.]+)""",
    """\Wrt=({time}\d+)""",
    """\Wcs3=({direction}.+?)\s+(\w+=|$)""",
    """\Wcs2=({location_door}.+?)\s+(\w+=|$)""",
    """\Wcs1=({location_building}.+?)\s+(\w+=|$)""",
    """\Wsuser=({user}[^\s]+)""",
    """\Wsuid=({user_fullname}.+?)\s+(\w+=|$)""",
  ]
}

${OAMParserTemplates.oam-app-activity}{
  Name = q-oam-auth-successful
  DataType = "authentication-successful"
  Conditions = [ """ IAU_RESOURCEHOST: """", """IAU_USERID: """", """ IAU_EVENTTYPE: "Authentication""""  ]
}

${OAMParserTemplates.oam-app-activity}{
  Name = q-oam-app-activity-2
  DataType = "app-activity"
  Conditions = [ """ IAU_RESOURCEHOST: """", """IAU_USERID: """", """ IAU_EVENTTYPE: "AuthenticationAttempt""""  ]
}

${OAMParserTemplates.oam-app-activity}{
  Name = q-oam-app-activity-3
  DataType = "app-activity"
  Conditions = [ """ IAU_RESOURCEHOST: """", """IAU_USERID: """", """ IAU_EVENTTYPE: "Authorization""""  ]
}

${OAMParserTemplates.oam-app-activity}{
  Name = q-oam-app-activity-4
  DataType = "app-activity"
  Conditions = [ """ IAU_RESOURCEHOST: """", """IAU_USERID: """", """ IAU_EVENTTYPE: "CredentialChallenge""""  ]
}

${OAMParserTemplates.oam-app-activity}{
  Name = q-oam-app-activity-5
  DataType = "app-activity"
  Conditions = [ """ IAU_RESOURCEHOST: """", """IAU_USERID: """", """ IAU_EVENTTYPE: "CredentialSubmit""""  ]
}

${OAMParserTemplates.oam-app-activity}{
  Name = q-oam-app-activity-6
  DataType = "app-activity"
  Conditions = [ """ IAU_RESOURCEHOST: """", """IAU_USERID: """", """ IAU_EVENTTYPE: "CredentialValidation""""  ]
}

${OAMParserTemplates.oam-app-activity}{
  Name = q-oam-app-activity-7
  DataType = "app-activity"
  Conditions = [ """ IAU_RESOURCEHOST: """", """IAU_USERID: """", """ IAU_EVENTTYPE: "PluginInvocationComplete""""  ]
}

${OAMParserTemplates.oam-app-activity}{
  Name = q-oam-app-activity-8
  DataType = "app-activity"
  Conditions = [ """ IAU_RESOURCEHOST: """", """IAU_USERID: """", """ IAU_EVENTTYPE: "PluginInvocationPause""""  ]
}

${OAMParserTemplates.oam-app-activity}{
  Name = q-oam-app-activity-9
  DataType = "app-activity"
  Conditions = [ """ IAU_RESOURCEHOST: """", """IAU_USERID: """", """ IAU_EVENTTYPE: "PluginInvocationResume""""  ]
}

${OAMParserTemplates.oam-app-activity}{
  Name = q-oam-app-activity-10
  DataType = "app-activity"
  Conditions = [ """ IAU_RESOURCEHOST: """", """IAU_USERID: """", """ IAU_EVENTTYPE: "PluginInvocationStart""""  ]
}

${OAMParserTemplates.oam-app-activity}{
  Name = q-oam-app-activity-11
  DataType = "app-activity"
  Conditions = [ """ IAU_RESOURCEHOST: """", """IAU_USERID: """", """ IAU_EVENTTYPE: "SessionCreation""""  ]
}

${OAMParserTemplates.oam-app-activity}{
  Name = q-oam-app-activity-12
  DataType = "app-activity"
  Conditions = [ """ IAU_RESOURCEHOST: """", """IAU_USERID: """", """ IAU_EVENTTYPE: "SessionDestroy""""  ]
}

${OAMParserTemplates.oam-app-activity}{
  Name = q-oam-app-login
  DataType = "app-login"
  Conditions = [ """ IAU_RESOURCEHOST: """", """IAU_USERID: """", """ IAU_EVENTTYPE: "Login""""  ]
}

{
  Name = s-oam-app-login
  Vendor = OAM
  Product = Oracle Access Manager
  Lms = Splunk
  DataType = "app-login"
  IsHVF = true
  TimeFormat = "MM/dd/yyyy HH:mm:ss z"
  Conditions = [ """| AUTHN_""", """OAM_LOGIN |""", """|uid=""" ]
  Fields = [
    """({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d \w+)\s*\|""",
    """([^\|]*\|){1}\s*({outcome}[^\|]+?)\s*\|""",
    """([^\|]*\|){2}\s*({host}[^\|]+?)\s*\|""",
    """([^\|]*\|){3}\s*({additional_info}[^\|]+?)\s*\|""",
    """([^\|]*\|){5}\s*({auth_method}[^\|]+?)\s*\|""",
    """([^\|]*\|){6}\s*({app}[^\|]+?)_LOGIN\s*\|""",
    """([^\|]*\|){7}\s*uid=({user}[^\|\s]+)""",
  ]
}
```