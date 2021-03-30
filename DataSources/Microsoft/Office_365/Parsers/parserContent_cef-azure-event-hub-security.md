#### Parser Content
```Java
{
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
cef-azure-event-hub = {
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Direct 
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [  """CEF:""",   """|Skyformation|SkyFormation Cloud Apps Security|""",   """destinationServiceName=Azure dproc=EventHub""" ]

```